package infrastructure

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/domain/identity"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
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
	// caller ends it with KeyPair.Close once the signature is made; here it is
	// released only on the error paths, where no key escapes.
	pairs, err := context.Pairs()
	if err != nil {
		_ = context.Close()
		return KeyPair{}, fmt.Errorf("list certificates on %s: %w", tokenName(signer), err)
	}
	if len(pairs) == 0 {
		_ = context.Close()
		return KeyPair{}, fmt.Errorf(
			"%s exposes no certificate paired with a private key.\n"+
				"  list it with: pkcs11-tool --module %s -O",
			tokenName(signer), signer.PKCS11Module(),
		)
	}

	leaves := make([]*x509.Certificate, len(pairs))
	for index, pair := range pairs {
		// An unreadable certificate stays nil: it cannot be chosen, and it must
		// not shift the position of the others.
		leaves[index], _ = brainpool.ParseCertificate(pair.Certificate)
	}
	index, err := signer.CertificateChoice().Pick(leaves)
	if err != nil {
		_ = context.Close()
		return KeyPair{}, choiceFailure(signer, leaves, err)
	}
	pair, leaf := pairs[index], leaves[index]
	if leaf == nil {
		_ = context.Close()
		return KeyPair{}, fmt.Errorf("%s holds a certificate that cannot be read", tokenName(signer))
	}

	var chain []*x509.Certificate
	for _, raw := range pair.Chain {
		parsed, err := brainpool.ParseCertificate(raw)
		if err != nil {
			continue
		}
		chain = append(chain, parsed)
	}

	var neighbours []*x509.Certificate
	for other, certificate := range leaves {
		if other != index && certificate != nil {
			neighbours = append(neighbours, certificate)
		}
	}

	return KeyPair{
		Signer:      pair.Signer,
		Certificate: leaf,
		Chain:       chain,
		Neighbours:  neighbours,
		Name:        signer.NameFor(identity.FromCertificate(leaf).Name),
		SelfSigned:  isSelfSigned(leaf),
		KeySource:   domain.FromToken,
		release:     context.Close,
	}, nil
}

// tokenName names the token in messages: by its label, or as the card found in
// the readers when no label was given.
func tokenName(signer domain.Signer) string {
	if signer.PKCS11Token() == "" {
		return "the card in the reader"
	}
	return fmt.Sprintf("token %q", signer.PKCS11Token())
}

// choiceFailure explains why no certificate was chosen and lists the ones the
// card holds, with what names each of them.
func choiceFailure(signer domain.Signer, leaves []*x509.Certificate, cause error) error {
	var listing strings.Builder
	for _, leaf := range leaves {
		if leaf == nil {
			continue
		}
		fmt.Fprintf(&listing, "\n  - %s  serial %s  fingerprint %s  usage %s",
			identity.FromCertificate(leaf).Name, leaf.SerialNumber.Text(16),
			domain.Fingerprint(leaf), strings.Join(usageNames(leaf), ","))
	}
	if errors.Is(cause, domain.ErrNoCertificateMatches) {
		return fmt.Errorf("%w %q (%s); it holds:%s",
			cause, signer.CertificateChoice().String(), tokenName(signer), listing.String())
	}
	return fmt.Errorf("%w (%s); choose one by its serial or fingerprint:%s",
		cause, tokenName(signer), listing.String())
}
