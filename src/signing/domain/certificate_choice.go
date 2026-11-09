package domain

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
)

var (
	// ErrNoCertificateMatches means the card holds no certificate the choice
	// accepts.
	ErrNoCertificateMatches = errors.New("no certificate on the card matches")

	// ErrSeveralCertificates means more than one certificate could sign and
	// nothing tells them apart.
	ErrSeveralCertificates = errors.New("several certificates on the card can sign")
)

// minimumFingerprintPrefix is the shortest fingerprint prefix accepted: fewer
// digits match another certificate too easily.
const minimumFingerprintPrefix = 8

// CertificateChoice decides which certificate of a card signs.
//
// A card often holds more than one: the Spanish DNIe and most Italian
// signature cards carry one certificate to authenticate and one to sign, and
// only the second declares non-repudiation. The person can name the one they
// want by the serial number or the SHA-256 fingerprint the token listing
// prints; without a name the choice is made only when the card leaves no doubt.
type CertificateChoice struct {
	selector string
}

// ChooseCertificateBy builds the choice from what the person typed. Spaces,
// colons, letter case and a leading "0x" are ignored, so a serial or a
// fingerprint copied from any tool is accepted as it is.
func ChooseCertificateBy(selector string) CertificateChoice {
	normalised := strings.ToLower(strings.TrimSpace(selector))
	normalised = strings.TrimPrefix(normalised, "0x")
	normalised = strings.NewReplacer(":", "", " ", "").Replace(normalised)
	return CertificateChoice{selector: normalised}
}

// Automatic reports whether the card decides: no certificate was named.
func (c CertificateChoice) Automatic() bool { return c.selector == "" }

// String returns the normalised selector.
func (c CertificateChoice) String() string { return c.selector }

// Pick returns the position of the chosen certificate among the candidates.
func (c CertificateChoice) Pick(candidates []*x509.Certificate) (int, error) {
	if len(candidates) == 0 {
		return 0, ErrNoCertificateMatches
	}
	if c.Automatic() {
		return pickForSigning(candidates)
	}

	matches := make([]int, 0, 1)
	for index, candidate := range candidates {
		if c.matches(candidate) {
			matches = append(matches, index)
		}
	}
	switch len(matches) {
	case 0:
		return 0, ErrNoCertificateMatches
	case 1:
		return matches[0], nil
	default:
		return 0, ErrSeveralCertificates
	}
}

// matches reports whether the certificate carries the serial or the
// fingerprint the person named.
func (c CertificateChoice) matches(candidate *x509.Certificate) bool {
	if candidate == nil {
		return false
	}
	serial := strings.TrimLeft(c.selector, "0")
	if serial != "" && candidate.SerialNumber.Text(16) == serial {
		return true
	}
	return len(c.selector) >= minimumFingerprintPrefix &&
		strings.HasPrefix(Fingerprint(candidate), c.selector)
}

// pickForSigning chooses without a name: the only certificate that can sign
// a document, or the only one of those that declares non-repudiation. A
// certificate authority's certificate never signs a document, and a store such
// as Firefox's holds several.
func pickForSigning(candidates []*x509.Certificate) (int, error) {
	var eligible []int
	for index, candidate := range candidates {
		if candidate != nil && !(candidate.BasicConstraintsValid && candidate.IsCA) {
			eligible = append(eligible, index)
		}
	}
	switch {
	case len(eligible) == 1:
		return eligible[0], nil
	case len(candidates) == 1:
		// The only pair a card offers is tried even when it cannot be read
		// here; the signer reports what is wrong with it.
		return 0, nil
	}

	chosen := -1
	for _, index := range eligible {
		if candidates[index].KeyUsage&x509.KeyUsageContentCommitment == 0 {
			continue
		}
		if chosen >= 0 {
			return 0, ErrSeveralCertificates
		}
		chosen = index
	}
	if chosen < 0 {
		return 0, ErrSeveralCertificates
	}
	return chosen, nil
}

// Fingerprint is the SHA-256 digest of the certificate in lowercase
// hexadecimal, the form the token listing prints.
func Fingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}
