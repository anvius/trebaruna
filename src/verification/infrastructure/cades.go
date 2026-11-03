package infrastructure

import (
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"codeberg.org/simplicer/firma-it/src/verification/domain"
	"github.com/digitorus/pkcs7"
)

// CadesVerifier verifies CAdES containers (.p7m).
//
// The library exposes signed attributes but not unsigned ones, and the RFC 3161
// token lives in unsignedAttrs. Rather than reparse the whole structure by hand,
// the token is located in the raw DER and handed to the timestamp package, which
// does understand it. That keeps the parsing risk confined to finding an offset.
type CadesVerifier struct {
	// Roots is the trusted root pool. Nil tells the library to use its own
	// defaults, which means "do not trust the embedded certificates".
	Roots *x509.CertPool
	// Now is the evaluation instant, injected for tests.
	Now time.Time
}

// NewCadesVerifier builds the adapter.
func NewCadesVerifier() *CadesVerifier {
	return &CadesVerifier{Now: time.Now()}
}

// Extract verifies a CMS container and returns one report.
func (v *CadesVerifier) Extract(path string) ([]domain.SignerReport, error) {
	if err := FileExists(path); err != nil {
		return nil, err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	parsed, err := pkcs7.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("parse CMS in %q: %w", path, err)
	}

	if len(parsed.Signers) != 1 {
		return nil, fmt.Errorf("CMS verification currently requires exactly one signer; found %d", len(parsed.Signers))
	}

	report := domain.SignerReport{
		FieldName: "CMS",
		Format:    "CAdES",
	}

	// Integrity: the detached/embedded content must still match the digest.
	if err := verifyContent(parsed); err != nil {
		report.Integrity = domain.StatusBad
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.modified",
			Status:  domain.StatusBad,
			Message: "the signed content does not match the signature",
			Detail:  err.Error(),
		})
	} else {
		report.Integrity = domain.StatusGood
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.intact",
			Status:  domain.StatusGood,
			Message: "the signed content is unaltered",
		})
	}

	signer := parsed.GetOnlySigner()
	describeCertificate(signer, &report)

	v.describeTime(content, parsed, &report)

	if signer != nil {
		switch {
		case report.SelfSigned:
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "certificate.self_signed",
				Status:  domain.StatusWarn,
				Message: "the certificate is self-signed: valid cryptography, no third-party trust",
			})
		case verifyCMSChain(parsed, v.Roots, v.Now) == nil:
			report.CertificateStatus = domain.StatusGood
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "certificate.trusted",
				Status:  domain.StatusGood,
				Message: "the issuer is a recognised authority",
			})
		default:
			report.CertificateStatus = domain.StatusUnknown
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "certificate.untrusted_issuer",
				Status:  domain.StatusUnknown,
				Message: "the issuer is not in any trusted list",
			})
		}
	}

	report.Trust = trustFromReport(report)
	return []domain.SignerReport{report}, nil
}

// verifyContent checks the signature against the carried content.
func verifyContent(parsed *pkcs7.PKCS7) error {
	// VerifyWithOpts with nil Roots checks cryptography without conflating
	// current certificate validity and content integrity.
	return parsed.VerifyWithOpts(x509.VerifyOptions{CurrentTime: time.Now()})
}

func verifyCMSChain(parsed *pkcs7.PKCS7, roots *x509.CertPool, now time.Time) error {
	if roots == nil {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return err
		}
	}
	if now.IsZero() {
		now = time.Now()
	}
	return parsed.VerifyWithChainAtTime(roots, now)
}

// No CMS timestamp is accepted as authoritative until its signature, imprint
// binding to the SignerInfo signature value and TSA trust chain are validated.
func (v *CadesVerifier) describeTime(content []byte, parsed *pkcs7.PKCS7, report *domain.SignerReport) {
	if claimed, err := signedSigningTime(parsed); err == nil {
		report.SignedAt = claimed
	}
	if findTimeStampToken(content) != nil {
		report.Findings = append(report.Findings, domain.Finding{
			Code: "verification.warning", Status: domain.StatusWarn,
			Message: "CMS timestamp present but not authenticated; it is not used as proof of signing time",
		})
	}
}

// signedSigningTime reads the signingTime signed attribute.
func signedSigningTime(parsed *pkcs7.PKCS7) (time.Time, error) {
	var encoded time.Time
	err := parsed.UnmarshalSignedAttribute(oidSigningTimeAttribute, &encoded)
	return encoded, err
}

// trustFromReport reduces the findings into a level.
func trustFromReport(report domain.SignerReport) domain.TrustLevel {
	if report.Integrity == domain.StatusBad {
		return domain.TrustBroken
	}
	if report.SelfSigned {
		return domain.TrustUntrusted
	}
	if report.CertificateStatus == domain.StatusUnknown {
		return domain.TrustUntrusted
	}
	return domain.TrustAdvanced
}

// compile-time check.
var _ SignatureExtractor = (*CadesVerifier)(nil)
