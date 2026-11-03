// Package infrastructure verifies documents with real cryptographic libraries.
//
// The adapters translate a library response into the verification domain. They
// do not decide trust: that is the use case's job, because it needs the trust
// list and the clock, which are external inputs.
package infrastructure

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"codeberg.org/simplicer/firma-it/src/signing/domain/identity"
	"codeberg.org/simplicer/firma-it/src/verification/domain"
)

// SignatureExtractor reads the signatures a document carries.
//
// Two implementations exist (PDF and CMS) because the container differs; the
// report domain is shared, which is what lets one CLI verb serve both.
type SignatureExtractor interface {
	// Extract returns one report per signature, with integrity already checked.
	Extract(path string) ([]domain.SignerReport, error)
}

// CertificateValidator resolves the chain for a signing certificate.
type CertificateValidator interface {
	// Validate returns the issuer verdict plus the revocation moment, if known.
	Validate(certificate *x509.Certificate, intermediates []*x509.Certificate) (IssuerVerdict, error)
}

// IssuerVerdict mirrors the trust domain verdict so adapters do not import it.
type IssuerVerdict struct {
	// Provider is "qualified", "public", "self-signed" or "unknown".
	Provider string
	// Trusted reports whether the chain validated against a known root.
	Trusted bool
	// Qualified reports whether the issuer is a listed qualified provider.
	Qualified bool
	// Reason explains the outcome in English.
	Reason string
}

// describeCertificate builds the identity fields every report needs.
//
// Reusing the signing-side identity package keeps the same name and identifier
// on both sides: what you signed is what the verifier shows back.
func describeCertificate(certificate *x509.Certificate, report *domain.SignerReport) {
	if certificate == nil {
		return
	}

	holder := identity.FromCertificate(certificate)
	report.SignerName = holder.Name
	report.Identifier = holder.Identifier
	report.Issuer = firstNonEmpty(
		firstOf(certificate.Issuer.Organization),
		certificate.Issuer.CommonName,
	)
	report.NotBefore = certificate.NotBefore
	report.NotAfter = certificate.NotAfter
	report.SelfSigned = bytes.Equal(certificate.RawIssuer, certificate.RawSubject) &&
		certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) == nil
}

// firstOf returns the first non-empty entry of a slice.
func firstOf(values []string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// FileExists reports whether a path is readable, with an actionable error.
//
// Verification is often the first thing a user does with a file they were sent,
// so a missing or unreadable path must say so plainly.
func FileExists(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("the file %q does not exist", path)
		}
		return fmt.Errorf("cannot read %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%q is a directory, not a document", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("%q is empty", path)
	}
	return nil
}

// decodeBase64Element decodes base64 text that may contain line breaks.
func decodeBase64Element(text string) []byte {
	cleaned := make([]byte, 0, len(text))
	for index := 0; index < len(text); index++ {
		character := text[index]
		if character == ' ' || character == '\n' || character == '\r' || character == '\t' {
			continue
		}
		cleaned = append(cleaned, character)
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(cleaned)))
	written, err := base64.StdEncoding.Decode(decoded, cleaned)
	if err != nil {
		return nil
	}
	return decoded[:written]
}
