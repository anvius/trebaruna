// Package keybundle opens PKCS#12 files (.p12, .pfx): a certificate, its
// private key and, usually, the chain above it, locked with a passphrase.
//
// DER files go to go-pkcs12, which knows every legacy algorithm. Files in BER,
// the encoding NSS writes for every Firefox and Thunderbird export, are read
// here, because go-pkcs12 rejects them before looking at the passphrase.
package keybundle

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"strings"
	"unicode/utf16"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Decode returns the private key, the certificate that belongs to it and the
// remaining certificates. A wrong passphrase is reported as
// pkcs12.ErrIncorrectPassword whatever the encoding.
func Decode(data []byte, password string) (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	key, certificate, chain, err := pkcs12.DecodeChain(data, password)
	if err == nil || errors.Is(err, pkcs12.ErrIncorrectPassword) || !notDER(err) {
		return key, certificate, chain, err
	}
	return decodeBER(data, password)
}

// notDER recognises go-pkcs12 giving up on the encoding rather than the content.
func notDER(err error) bool {
	message := err.Error()
	return strings.Contains(message, "not DER") || strings.Contains(message, "indefinite length")
}

var (
	oidData                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidKeyBag               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidShroudedKeyBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Certificate      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidSHA1                 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	errUnsupportedAlgorithm = errors.New("keybundle: unsupported algorithm")
)

type pfx struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type encryptedData struct {
	Version int
	Info    encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Algorithm   pkix.AlgorithmIdentifier
	Content     asn1.RawValue `asn1:"tag:0,optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue   `asn1:"tag:0,explicit"`
	Attributes []asn1.RawValue `asn1:"set,optional"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// decodeBER reads a PKCS#12 file that is not DER.
func decodeBER(data []byte, password string) (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	normalised, err := derFromBER(data)
	if err != nil {
		return nil, nil, nil, err
	}
	var file pfx
	if err := unmarshalAll(normalised, &file); err != nil {
		return nil, nil, nil, fmt.Errorf("keybundle: not a PKCS#12 file: %w", err)
	}
	if file.Version != 3 || !file.AuthSafe.ContentType.Equal(oidData) {
		return nil, nil, nil, errors.New("keybundle: not a password-protected PKCS#12 file")
	}

	// The MAC covers the authenticated safe exactly as written, BER included,
	// so it is checked on these bytes before they are normalised.
	var authSafe []byte
	if _, err := asn1.Unmarshal(file.AuthSafe.Content.Bytes, &authSafe); err != nil {
		return nil, nil, nil, fmt.Errorf("keybundle: unreadable authenticated safe: %w", err)
	}
	if err := verifyMAC(file.MacData, authSafe, password); err != nil {
		return nil, nil, nil, err
	}

	normalisedSafe, err := derFromBER(authSafe)
	if err != nil {
		return nil, nil, nil, err
	}
	var parts []contentInfo
	if err := unmarshalAll(normalisedSafe, &parts); err != nil {
		return nil, nil, nil, fmt.Errorf("keybundle: unreadable authenticated safe: %w", err)
	}

	var keys []crypto.PrivateKey
	var certificates []*x509.Certificate
	for _, part := range parts {
		bags, err := safeContents(part, password)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, bag := range bags {
			switch {
			case bag.ID.Equal(oidKeyBag):
				key, err := x509.ParsePKCS8PrivateKey(bag.Value.Bytes)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("keybundle: unreadable private key: %w", err)
				}
				keys = append(keys, key)
			case bag.ID.Equal(oidShroudedKeyBag):
				key, err := shroudedKey(bag.Value.Bytes, password)
				if err != nil {
					return nil, nil, nil, err
				}
				keys = append(keys, key)
			case bag.ID.Equal(oidCertBag):
				certificate, err := certificateFrom(bag.Value.Bytes)
				if err != nil {
					return nil, nil, nil, err
				}
				if certificate != nil {
					certificates = append(certificates, certificate)
				}
			}
		}
	}
	return pair(keys, certificates)
}

// safeContents returns the bags of one part, decrypting it if needed.
func safeContents(part contentInfo, password string) ([]safeBag, error) {
	var plain []byte
	switch {
	case part.ContentType.Equal(oidData):
		if _, err := asn1.Unmarshal(part.Content.Bytes, &plain); err != nil {
			return nil, fmt.Errorf("keybundle: unreadable data part: %w", err)
		}
	case part.ContentType.Equal(oidEncryptedData):
		var encrypted encryptedData
		if err := unmarshalAll(part.Content.Bytes, &encrypted); err != nil {
			return nil, fmt.Errorf("keybundle: unreadable encrypted part: %w", err)
		}
		ciphertext, err := octets(encrypted.Info.Content)
		if err != nil {
			return nil, err
		}
		if plain, err = decrypt(encrypted.Info.Algorithm, ciphertext, password); err != nil {
			return nil, err
		}
	default:
		// Public-key encrypted parts are not passphrase bundles; skip them.
		return nil, nil
	}

	normalised, err := derFromBER(plain)
	if err != nil {
		return nil, err
	}
	var bags []safeBag
	if err := unmarshalAll(normalised, &bags); err != nil {
		return nil, fmt.Errorf("keybundle: unreadable bags: %w", err)
	}
	return bags, nil
}

// octets reads an implicitly tagged OCTET STRING that BER may have split.
func octets(value asn1.RawValue) ([]byte, error) {
	if !value.IsCompound {
		return value.Bytes, nil
	}
	var joined []byte
	rest := value.Bytes
	for len(rest) > 0 {
		var piece []byte
		var err error
		if rest, err = asn1.Unmarshal(rest, &piece); err != nil {
			return nil, fmt.Errorf("keybundle: unreadable encrypted content: %w", err)
		}
		joined = append(joined, piece...)
	}
	return joined, nil
}

func shroudedKey(encoded []byte, password string) (crypto.PrivateKey, error) {
	normalised, err := derFromBER(encoded)
	if err != nil {
		return nil, err
	}
	var info encryptedPrivateKeyInfo
	if err := unmarshalAll(normalised, &info); err != nil {
		return nil, fmt.Errorf("keybundle: unreadable encrypted key: %w", err)
	}
	plain, err := decrypt(info.Algorithm, info.Data, password)
	if err != nil {
		return nil, err
	}
	if plain, err = derFromBER(plain); err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("keybundle: unreadable private key: %w", err)
	}
	return key, nil
}

func certificateFrom(encoded []byte) (*x509.Certificate, error) {
	var bag certBag
	if _, err := asn1.Unmarshal(encoded, &bag); err != nil {
		return nil, fmt.Errorf("keybundle: unreadable certificate bag: %w", err)
	}
	if !bag.ID.Equal(oidX509Certificate) {
		return nil, nil
	}
	certificate, err := x509.ParseCertificate(bag.Data)
	if err != nil {
		return nil, fmt.Errorf("keybundle: unreadable certificate: %w", err)
	}
	return certificate, nil
}

// pair finds the certificate that belongs to the key; the rest is the chain.
func pair(keys []crypto.PrivateKey, certificates []*x509.Certificate) (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	if len(keys) != 1 {
		return nil, nil, nil, fmt.Errorf("keybundle: expected one private key, found %d", len(keys))
	}
	signer, ok := keys[0].(crypto.Signer)
	if !ok {
		return nil, nil, nil, errors.New("keybundle: the private key cannot sign")
	}
	type comparable interface{ Equal(crypto.PublicKey) bool }
	public, ok := signer.Public().(comparable)
	if !ok {
		return nil, nil, nil, errors.New("keybundle: unsupported key type")
	}
	for index, certificate := range certificates {
		if public.Equal(certificate.PublicKey) {
			chain := append(append([]*x509.Certificate{}, certificates[:index]...), certificates[index+1:]...)
			return keys[0], certificate, chain, nil
		}
	}
	return nil, nil, nil, errors.New("keybundle: no certificate matches the private key")
}

// verifyMAC checks the integrity MAC (RFC 7292 §5) with the passphrase.
func verifyMAC(mac macData, content []byte, password string) error {
	newHash, err := hashFor(mac.Mac.Algorithm.Algorithm)
	if err != nil {
		return err
	}
	if mac.Iterations < 1 {
		return errors.New("keybundle: invalid MAC iteration count")
	}
	// An empty passphrase is written either as an empty BMPString or as nothing
	// at all, depending on the exporter; both are tried.
	for _, encoded := range bmpPasswords(password) {
		key := derive(newHash, mac.MacSalt, encoded, mac.Iterations, 3, newHash().Size())
		check := hmac.New(newHash, key)
		check.Write(content)
		if hmac.Equal(check.Sum(nil), mac.Mac.Digest) {
			return nil
		}
	}
	return pkcs12.ErrIncorrectPassword
}

func hashFor(algorithm asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case algorithm.Equal(oidSHA1):
		return sha1.New, nil
	case algorithm.Equal(oidSHA256):
		return sha256.New, nil
	case algorithm.Equal(oidSHA384):
		return sha512.New384, nil
	case algorithm.Equal(oidSHA512):
		return sha512.New, nil
	}
	return nil, fmt.Errorf("%w: MAC digest %v", errUnsupportedAlgorithm, algorithm)
}

// bmpPasswords encodes a passphrase as PKCS#12 does for its own KDF:
// big-endian UTF-16 with a two-byte terminator.
func bmpPasswords(password string) [][]byte {
	var encoded bytes.Buffer
	for _, unit := range utf16.Encode([]rune(password)) {
		encoded.WriteByte(byte(unit >> 8))
		encoded.WriteByte(byte(unit))
	}
	encoded.Write([]byte{0, 0})
	if password == "" {
		return [][]byte{encoded.Bytes(), nil}
	}
	return [][]byte{encoded.Bytes()}
}

// unmarshalAll parses DER and refuses trailing bytes.
func unmarshalAll(der []byte, out any) error {
	rest, err := asn1.Unmarshal(der, out)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("%d trailing bytes", len(rest))
	}
	return nil
}
