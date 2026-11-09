// Package domain holds the rules of encrypted envelopes (.p7e): who can
// receive one and where the files go.
package domain

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrNoRecipients means nobody was named to open the envelope.
	ErrNoRecipients = errors.New("an envelope needs at least one recipient certificate")

	// ErrCannotReceive means a certificate is not meant for receiving keys.
	ErrCannotReceive = errors.New("this certificate cannot receive an encrypted envelope")

	// ErrRecipientExpired means the certificate is no longer valid: its
	// holder may no longer have the key that opens the envelope.
	ErrRecipientExpired = errors.New("the recipient's certificate has expired")
)

// Envelope is an encrypted document written to disk.
type Envelope struct {
	Path       string
	Size       int
	Recipients []string
}

// Decrypted is a document taken out of its envelope.
type Decrypted struct {
	Path string
	Size int
}

// EncryptedName is where an envelope goes: beside the document, with .p7e.
func EncryptedName(document string) string { return document + ".p7e" }

// DecryptedName is where the document of an envelope goes: the envelope's
// name without .p7e, or with .decrypted when it has no such suffix.
func DecryptedName(envelope string) string {
	if strings.HasSuffix(strings.ToLower(envelope), ".p7e") && len(envelope) > 4 {
		return envelope[:len(envelope)-4]
	}
	return envelope + ".decrypted"
}

// CanReceive checks a recipient certificate before anything is encrypted to
// it: an RSA key (key transport), a key usage that allows key encipherment
// when one is declared — a signature-only certificate must not be used — and
// a validity that has not ended.
func CanReceive(certificate *x509.Certificate, now time.Time) error {
	name := certificate.Subject.CommonName
	if _, isRSA := certificate.PublicKey.(*rsa.PublicKey); !isRSA {
		return fmt.Errorf("%w: %s has a %T key, and only RSA keys receive envelopes", ErrCannotReceive, name, certificate.PublicKey)
	}
	if certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return fmt.Errorf("%w: %s is for signing only (no keyEncipherment)", ErrCannotReceive, name)
	}
	if now.After(certificate.NotAfter) {
		return fmt.Errorf("%w: %s, on %s", ErrRecipientExpired, name, certificate.NotAfter.Format("2006-01-02"))
	}
	return nil
}
