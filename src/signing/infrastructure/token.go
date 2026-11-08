package infrastructure

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// tokenPair is a certificate together with its signing key, as the token
// exposes it. Keeping our own type here means the cgo adapter can translate
// from any PKCS#11 library without leaking it into this layer.
type tokenPair struct {
	Certificate []byte
	Chain       [][]byte
	Signer      crypto.Signer
}

// tokenContext is the capability the adapter needs from a PKCS#11 session.
type tokenContext interface {
	Pairs() ([]tokenPair, error)
	Close() error
}

// loadToken opens a PKCS#11 token and pairs the certificate with its key.
//
// It lives in its own file so builds without CGO can exclude the driver with a
// build tag, keeping the base binary fully static.
func loadToken(signer domain.Signer) (KeyPair, error) {
	context, err := openToken(signer)
	if err != nil {
		return KeyPair{}, err
	}

	// The session must stay open: the crypto.Signer returned below signs through
	// it, and closing here produced "context is closed" on every signature. The
	// context is released only on the error paths, where no key escapes.
	pairs, err := context.Pairs()
	if err != nil {
		_ = context.Close()
		return KeyPair{}, fmt.Errorf("list certificates on token %q: %w", signer.PKCS11Token(), err)
	}
	if len(pairs) == 0 {
		_ = context.Close()
		return KeyPair{}, fmt.Errorf(
			"token %q exposes no certificate paired with a private key.\n"+
				"  list it with: pkcs11-tool --module %s -O",
			signer.PKCS11Token(), signer.PKCS11Module(),
		)
	}

	pair := pairs[0]
	leaf, err := x509.ParseCertificate(pair.Certificate)
	if err != nil {
		_ = context.Close()
		return KeyPair{}, fmt.Errorf("parse token certificate: %w", err)
	}

	var chain []*x509.Certificate
	for _, raw := range pair.Chain {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		chain = append(chain, parsed)
	}

	return KeyPair{
		Signer:      pair.Signer,
		Certificate: leaf,
		Chain:       chain,
		Name:        signer.Name(),
		SelfSigned:  isSelfSigned(leaf),
		KeySource:   domain.FromToken,
	}, nil
}
