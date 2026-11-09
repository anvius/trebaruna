package domain

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrNoSavedRecipient means the address book holds no certificate that
	// matches what was asked.
	ErrNoSavedRecipient = errors.New("no saved recipient matches")

	// ErrAmbiguousRecipient means more than one saved certificate matches.
	ErrAmbiguousRecipient = errors.New("more than one saved recipient matches; give more of the fingerprint")
)

// SavedRecipient is a certificate kept in the address book, to encrypt for
// its holder again without looking for the file.
type SavedRecipient struct {
	Holder string
	// Fingerprint is the certificate's SHA-256 in hex, its name in the book.
	Fingerprint string
	NotAfter    time.Time
	// Location is the file the certificate is kept in.
	Location string
}

// SavedFrom describes a certificate as the book keeps it.
func SavedFrom(certificate *x509.Certificate, location string) SavedRecipient {
	return SavedRecipient{Holder: holderOf(certificate), Fingerprint: Fingerprint(certificate), NotAfter: certificate.NotAfter, Location: location}
}

// Fingerprint is a certificate's SHA-256 in lower-case hex.
func Fingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}

// holderOf names the holder: the common name, else the whole subject.
func holderOf(certificate *x509.Certificate) string {
	if certificate.Subject.CommonName != "" {
		return certificate.Subject.CommonName
	}
	return certificate.Subject.String()
}

// Pick finds the one saved recipient a person means: the start of its
// fingerprint (colons and case ignored), or words of its holder's name.
func Pick(saved []SavedRecipient, wanted string) (SavedRecipient, error) {
	normalised := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(wanted), ":", ""))
	if normalised == "" {
		return SavedRecipient{}, fmt.Errorf("%w %q", ErrNoSavedRecipient, wanted)
	}
	var found []SavedRecipient
	for _, recipient := range saved {
		if strings.HasPrefix(recipient.Fingerprint, normalised) || strings.Contains(strings.ToLower(recipient.Holder), strings.ToLower(strings.TrimSpace(wanted))) {
			found = append(found, recipient)
		}
	}
	switch len(found) {
	case 0:
		return SavedRecipient{}, fmt.Errorf("%w %q", ErrNoSavedRecipient, wanted)
	case 1:
		return found[0], nil
	}
	return SavedRecipient{}, fmt.Errorf("%w: %q", ErrAmbiguousRecipient, wanted)
}
