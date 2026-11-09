// Package infrastructure implements the signing ports with real crypto.
//
// Every adapter here converts a domain.Signer into a crypto.Signer plus a
// certificate. That single conversion is what lets P12, PEM and smartcards
// share the whole pipeline afterwards.
package infrastructure

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/domain/identity"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/keybundle"
)

// KeyPair is a ready-to-use signing identity.
type KeyPair struct {
	Signer      crypto.Signer
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	Name        string
	SelfSigned  bool
	KeySource   domain.KeySource

	// release ends the card session the Signer works through; nil for keys
	// read from a file.
	release func() error
}

// Close ends the card session once the signature is made. A process that
// signs more than once, such as the local API, would otherwise hold every
// session open and keep seeing the readers as they were the first time.
func (k KeyPair) Close() error {
	if k.release == nil {
		return nil
	}
	return k.release()
}

// Certificates returns the leaf first, then the issuers.
func (k KeyPair) Certificates() []*x509.Certificate {
	return append([]*x509.Certificate{k.Certificate}, k.Chain...)
}

// LoadKeyPair resolves a domain.Signer into usable crypto material.
//
// It is the only place that knows how a key is stored.
func LoadKeyPair(signer domain.Signer) (KeyPair, error) {
	switch signer.KeySource() {
	case domain.FromP12:
		return loadP12(signer)
	case domain.FromPEM:
		return loadPEM(signer)
	case domain.FromToken:
		return loadToken(signer)
	case domain.FromRemote:
		return loadRemote(signer)
	}
	return KeyPair{}, domain.ErrSignerWithoutSource
}

// loadP12 decodes a PKCS#12 bundle. Self-signed certificates are accepted and
// flagged, never rejected: the user may be signing for internal use.
func loadP12(signer domain.Signer) (KeyPair, error) {
	// keybundle reads DER and the BER that Firefox and Thunderbird export.
	key, cert, chain, err := keybundle.Decode(signer.KeyMaterial(), signer.Passphrase())
	if err != nil {
		// Said in the person's terms: which file is wrong is theirs to
		// know, whether a passphrase was given is not.
		switch {
		case !strings.Contains(err.Error(), "password"):
			return KeyPair{}, fmt.Errorf("the PKCS#12 file cannot be read: %w", err)
		case signer.Passphrase() == "":
			return KeyPair{}, fmt.Errorf("the PKCS#12 file does not open without its passphrase: %w", err)
		}
		return KeyPair{}, fmt.Errorf("the passphrase does not open the PKCS#12 file: %w", err)
	}

	cryptoSigner, ok := key.(crypto.Signer)
	if !ok {
		return KeyPair{}, fmt.Errorf("p12 %q does not carry a usable private key", signer.Name())
	}

	return KeyPair{
		Signer:      cryptoSigner,
		Certificate: cert,
		Chain:       chain,
		Name:        signer.NameFor(identity.FromCertificate(cert).Name),
		SelfSigned:  isSelfSigned(cert),
		KeySource:   domain.FromP12,
	}, nil
}

// loadPEM reads a PEM bundle holding a certificate and a private key, in any
// order, optionally encrypted.
func loadPEM(signer domain.Signer) (KeyPair, error) {
	material := signer.KeyMaterial()
	passphrase := signer.Passphrase()

	var cert *x509.Certificate
	var chain []*x509.Certificate
	var key crypto.Signer

	remaining := material
	for {
		block, rest := nextPEMBlock(remaining)
		if block == nil {
			break
		}
		remaining = rest

		switch {
		case strings.Contains(block.Type, "CERTIFICATE"):
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return KeyPair{}, fmt.Errorf("parse certificate in %q: %w", signer.Name(), err)
			}
			if cert == nil {
				cert = parsed
			} else {
				chain = append(chain, parsed)
			}
		case strings.Contains(block.Type, "PRIVATE KEY"):
			parsed, err := parsePrivateKey(block.Bytes, passphrase)
			if err != nil {
				return KeyPair{}, fmt.Errorf("parse private key in %q: %w", signer.Name(), err)
			}
			key = parsed
		}
	}

	if cert == nil {
		return KeyPair{}, fmt.Errorf("no certificate found in PEM bundle %q", signer.Name())
	}
	if key == nil {
		return KeyPair{}, fmt.Errorf("no private key found in PEM bundle %q", signer.Name())
	}

	return KeyPair{
		Signer:      key,
		Certificate: cert,
		Chain:       chain,
		Name:        signer.NameFor(identity.FromCertificate(cert).Name),
		SelfSigned:  isSelfSigned(cert),
		KeySource:   domain.FromPEM,
	}, nil
}

// isSelfSigned reports whether the certificate is its own issuer and verifies
// against its own public key.
//
// CheckSignatureFrom is deliberately NOT used: it enforces KeyUsageCertSign on
// the issuer, and an end-entity signing certificate never carries CertSign.
// Using it would report every self-signed signing certificate as CA-issued,
// which is exactly the opposite of the truth.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Issuer.String() != cert.Subject.String() {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
