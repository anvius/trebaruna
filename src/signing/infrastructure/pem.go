package infrastructure

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/youmark/pkcs8"
)

// nextPEMBlock decodes the first PEM block, tolerating leading garbage.
func nextPEMBlock(data []byte) (*pem.Block, []byte) {
	for {
		block, rest := pem.Decode(data)
		if block != nil {
			return block, rest
		}
		if len(rest) == 0 {
			return nil, nil
		}
		data = rest
	}
}

// parsePrivateKey handles PKCS#8, PKCS#1 and EC keys, encrypted or not.
func parsePrivateKey(der []byte, passphrase string) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return asSigner(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if passphrase != "" {
		key, err := pkcs8.ParsePKCS8PrivateKey(der, []byte(passphrase))
		if err == nil {
			return asSigner(key)
		}
		return nil, fmt.Errorf("cannot decrypt private key: %w", err)
	}
	return nil, fmt.Errorf("unsupported private key format, or the key is encrypted and no passphrase was given")
}

// asSigner narrows an any to crypto.Signer.
func asSigner(key any) (crypto.Signer, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T cannot sign", key)
	}
	return signer, nil
}
