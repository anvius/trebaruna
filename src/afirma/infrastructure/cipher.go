package infrastructure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
)

// The intermediate server's ciphers (C.5, C.8). Single DES with a key of
// eight digits protects nothing against anyone who sees the traffic; it is
// implemented because the pages require it, and the person is told.

// DESEnvelope encrypts one item: zero-padded to the block, DES-ECB, written
// "N.base64url" where N is the number of padding bytes.
func DESEnvelope(key string, plain []byte) (string, error) {
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	padding := (8 - len(plain)%8) % 8
	padded := append(append([]byte{}, plain...), make([]byte, padding)...)
	encrypted := make([]byte, len(padded))
	for offset := 0; offset < len(padded); offset += 8 {
		block.Encrypt(encrypted[offset:offset+8], padded[offset:offset+8])
	}
	return strconv.Itoa(padding) + "." + base64.URLEncoding.EncodeToString(encrypted), nil
}

// OpenDESEnvelope decrypts "N.base64" (either alphabet; no "N." means 0).
func OpenDESEnvelope(key, text string) ([]byte, error) {
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	padding := 0
	if dot := strings.Index(text, "."); dot >= 0 {
		padding, err = strconv.Atoi(text[:dot])
		if err != nil || padding < 0 || padding > 7 {
			return nil, errors.New("unreadable padding count")
		}
		text = text[dot+1:]
	}
	encrypted, err := domain.DecodeBase64(text)
	if err != nil || len(encrypted)%8 != 0 || len(encrypted) < padding {
		return nil, errors.New("the ciphertext is not whole DES blocks")
	}
	plain := make([]byte, len(encrypted))
	for offset := 0; offset < len(encrypted); offset += 8 {
		block.Decrypt(plain[offset:offset+8], encrypted[offset:offset+8])
	}
	return plain[:len(plain)-padding], nil
}

// aesParameters is the cipher parameter of autoscript 1.10 (C.8).
type aesParameters struct {
	Algorithm string `json:"algo"`
	Key       string `json:"key"`
	IV        string `json:"iv"`
	LegacyDES string `json:"legDes"`
}

// readAES decodes the cipher parameter, or reports none.
func readAES(parameter string) (key, iv []byte, ok bool) {
	if parameter == "" {
		return nil, nil, false
	}
	decoded, err := domain.DecodeBase64(parameter)
	if err != nil {
		return nil, nil, false
	}
	var parameters aesParameters
	if json.Unmarshal(decoded, &parameters) != nil || !strings.EqualFold(parameters.Algorithm, "AES") {
		return nil, nil, false
	}
	key, keyErr := domain.DecodeBase64(parameters.Key)
	iv, ivErr := domain.DecodeBase64(parameters.IV)
	if keyErr != nil || ivErr != nil || len(key) != 32 || len(iv) != aes.BlockSize {
		return nil, nil, false
	}
	return key, iv, true
}

// AESEnvelope encrypts one item with AES-256-CBC and PKCS#7 padding, URL-safe
// Base64 without a prefix (AutoFirma 1.9.1's results).
func AESEnvelope(key, iv, plain []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// OpenAESEnvelope decrypts an AES-256-CBC item.
func OpenAESEnvelope(key, iv []byte, text string) ([]byte, error) {
	encrypted, err := domain.DecodeBase64(text)
	if err != nil || len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("the ciphertext is not whole AES blocks")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, encrypted)
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(plain) {
		return nil, errors.New("bad AES padding")
	}
	for _, value := range plain[len(plain)-padding:] {
		if int(value) != padding {
			return nil, errors.New("bad AES padding")
		}
	}
	return plain[:len(plain)-padding], nil
}

// sealItem ciphers one answer element for the channel: AES when the page sent
// the 1.10 cipher parameter, DES with its key otherwise.
func sealItem(channel domain.Channel, plain []byte) (string, error) {
	if key, iv, ok := readAES(channel.Cipher); ok {
		return AESEnvelope(key, iv, plain)
	}
	return DESEnvelope(channel.Key, plain)
}

// openRequest deciphers an uploaded request: AES first when the page sent the
// cipher parameter, falling back to DES as AutoFirma 1.9.1 does; plain
// Base64 without a key.
func openRequest(key, cipherParameter, text string) ([]byte, error) {
	if aesKey, iv, ok := readAES(cipherParameter); ok {
		if plain, err := OpenAESEnvelope(aesKey, iv, text); err == nil {
			return plain, nil
		}
	}
	if key == "" {
		return domain.DecodeBase64(text)
	}
	plain, err := OpenDESEnvelope(key, text)
	if err != nil {
		return nil, fmt.Errorf("decipher the request: %w", err)
	}
	return plain, nil
}
