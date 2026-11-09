package keybundle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var (
	oidPBES2                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1         = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC           = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidPBEWithSHAAnd3DESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
)

type pbes2Params struct {
	KDF        pkix.AlgorithmIdentifier
	Encryption pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

type legacyPBEParams struct {
	Salt       []byte
	Iterations int
}

// decrypt opens a part or a key with the passphrase. PBES2 is what NSS and
// modern OpenSSL write; 3DES with the PKCS#12 KDF covers older exports. RC2,
// the oldest scheme, is left to go-pkcs12, which only meets it in DER files.
func decrypt(algorithm pkix.AlgorithmIdentifier, ciphertext []byte, password string) ([]byte, error) {
	var block cipher.Block
	var iv []byte
	var err error

	switch {
	case algorithm.Algorithm.Equal(oidPBES2):
		block, iv, err = pbes2Cipher(algorithm.Parameters.FullBytes, password)
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd3DESCBC):
		block, iv, err = legacy3DESCipher(algorithm.Parameters.FullBytes, password)
	default:
		return nil, fmt.Errorf("%w: encryption %v", errUnsupportedAlgorithm, algorithm.Algorithm)
	}
	if err != nil {
		return nil, err
	}

	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 || len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("keybundle: malformed ciphertext")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	return unpad(plain, block.BlockSize())
}

func pbes2Cipher(parameters []byte, password string) (cipher.Block, []byte, error) {
	var params pbes2Params
	if err := unmarshalAll(parameters, &params); err != nil {
		return nil, nil, fmt.Errorf("keybundle: unreadable PBES2 parameters: %w", err)
	}
	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, nil, fmt.Errorf("%w: key derivation %v", errUnsupportedAlgorithm, params.KDF.Algorithm)
	}
	var kdf pbkdf2Params
	if err := unmarshalAll(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, nil, fmt.Errorf("keybundle: unreadable PBKDF2 parameters: %w", err)
	}

	prf, err := prfFor(kdf.PRF.Algorithm)
	if err != nil {
		return nil, nil, err
	}
	keyLength, newBlock, err := cipherFor(params.Encryption.Algorithm)
	if err != nil {
		return nil, nil, err
	}
	var iv []byte
	if err := unmarshalAll(params.Encryption.Parameters.FullBytes, &iv); err != nil {
		return nil, nil, fmt.Errorf("keybundle: unreadable IV: %w", err)
	}

	// PBES2 takes the passphrase as UTF-8 bytes, unlike the PKCS#12 KDF.
	key, err := pbkdf2.Key(prf, password, kdf.Salt, kdf.Iterations, keyLength)
	if err != nil {
		return nil, nil, err
	}
	block, err := newBlock(key)
	return block, iv, err
}

func prfFor(algorithm asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case len(algorithm) == 0, algorithm.Equal(oidHMACWithSHA1):
		return sha1.New, nil
	case algorithm.Equal(oidHMACWithSHA256):
		return sha256.New, nil
	case algorithm.Equal(oidHMACWithSHA384):
		return sha512.New384, nil
	case algorithm.Equal(oidHMACWithSHA512):
		return sha512.New, nil
	}
	return nil, fmt.Errorf("%w: PRF %v", errUnsupportedAlgorithm, algorithm)
}

func cipherFor(algorithm asn1.ObjectIdentifier) (int, func([]byte) (cipher.Block, error), error) {
	switch {
	case algorithm.Equal(oidAES128CBC):
		return 16, aes.NewCipher, nil
	case algorithm.Equal(oidAES192CBC):
		return 24, aes.NewCipher, nil
	case algorithm.Equal(oidAES256CBC):
		return 32, aes.NewCipher, nil
	case algorithm.Equal(oidDESEDE3CBC):
		return 24, des.NewTripleDESCipher, nil
	}
	return 0, nil, fmt.Errorf("%w: cipher %v", errUnsupportedAlgorithm, algorithm)
}

func legacy3DESCipher(parameters []byte, password string) (cipher.Block, []byte, error) {
	var params legacyPBEParams
	if err := unmarshalAll(parameters, &params); err != nil {
		return nil, nil, fmt.Errorf("keybundle: unreadable PBE parameters: %w", err)
	}
	encoded := bmpPasswords(password)[0]
	key := derive(sha1.New, params.Salt, encoded, params.Iterations, 1, 24)
	iv := derive(sha1.New, params.Salt, encoded, params.Iterations, 2, 8)
	block, err := des.NewTripleDESCipher(key)
	return block, iv, err
}

// unpad removes PKCS#7 padding. Bad padding after decryption almost always
// means the wrong passphrase, so it is reported as one.
func unpad(plain []byte, blockSize int) ([]byte, error) {
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > blockSize || padding > len(plain) {
		return nil, pkcs12.ErrIncorrectPassword
	}
	for _, value := range plain[len(plain)-padding:] {
		if int(value) != padding {
			return nil, pkcs12.ErrIncorrectPassword
		}
	}
	return plain[:len(plain)-padding], nil
}

// derive is the PKCS#12 key derivation (RFC 7292 appendix B.2), used for the
// integrity MAC (id 3) and the legacy cipher keys (1) and IVs (2).
func derive(newHash func() hash.Hash, salt, password []byte, iterations int, id byte, size int) []byte {
	digest := newHash()
	v := digest.BlockSize()

	diversifier := repeated(v, id)
	input := append(stretch(salt, v), stretch(password, v)...)

	var out []byte
	for len(out) < size {
		digest.Reset()
		digest.Write(diversifier)
		digest.Write(input)
		block := digest.Sum(nil)
		for round := 1; round < iterations; round++ {
			digest.Reset()
			digest.Write(block)
			block = digest.Sum(block[:0])
		}
		out = append(out, block...)

		// I_j = (I_j + B + 1) mod 2^(8v) for each v-byte block of the input.
		addend := stretch(block, v)
		for start := 0; start < len(input); start += v {
			carry := 1
			for index := v - 1; index >= 0; index-- {
				sum := int(input[start+index]) + int(addend[index]) + carry
				input[start+index] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return out[:size]
}

// stretch repeats data to the next multiple of v bytes; empty stays empty.
func stretch(data []byte, v int) []byte {
	if len(data) == 0 {
		return nil
	}
	length := v * ((len(data) + v - 1) / v)
	out := make([]byte, length)
	for index := range out {
		out[index] = data[index%len(data)]
	}
	return out
}

// repeated returns count copies of value.
func repeated(count int, value byte) []byte {
	out := make([]byte, count)
	for index := range out {
		out[index] = value
	}
	return out
}
