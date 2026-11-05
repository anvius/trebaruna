package infrastructure

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"codeberg.org/simplicer/firma-it/src/verification/application"
	"codeberg.org/simplicer/firma-it/src/verification/domain"
	"github.com/digitorus/pdfsign/verify"
)

// Poppler-free PDF verification: pdfsign parses the document, resolves every
// signature dictionary and checks the byte ranges. This adapter maps its
// response onto the report domain, keeping the library out of the use case.

// PDFVerifier verifies signed PDFs.
type PDFVerifier struct {
	// Roots is the trusted root pool. Nil means "system roots", resolved lazily.
	Roots *x509.CertPool
	// Now is the evaluation instant, injected so tests can freeze it.
	//
	// It used to be declared and never read, which meant a frozen clock in a test
	// had no effect on the library and the field was decoration.
	Now time.Time
	// CheckRevocation enables OCSP/CRL lookups. Off by default: a verification
	// that reaches the network must be an explicit choice.
	CheckRevocation bool
	// Intermediates complements Roots when the anchors come from a trust list.
	Intermediates *x509.CertPool
}

// WithAnchors returns a copy that validates chains against the given pools.
//
// This is what makes a qualified signature readable: the CA that issues
// document-signing certificates is not in the operating system store, so
// without the trust list every qualified signature would look untrusted.
//
// The return type is the application layer's extractor on purpose. Declaring it
// as this package's own SignatureExtractor is nominally a different type, so the
// use case's type assertion silently failed and the anchors were dropped: every
// qualified signature was reported as untrusted with a fully authenticated list.
func (v *PDFVerifier) WithAnchors(roots, intermediates *x509.CertPool) application.DocumentExtractor {
	clone := *v
	clone.Roots = roots
	clone.Intermediates = intermediates
	return &clone
}

// NewPDFVerifier builds the adapter with the current clock.
func NewPDFVerifier() *PDFVerifier {
	return &PDFVerifier{Now: time.Now()}
}

// Extract verifies every signature the document carries.
func (v *PDFVerifier) Extract(path string) ([]domain.SignerReport, error) {
	if err := FileExists(path); err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Stat(); err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}

	options := &verify.VerifyOptions{
		// Signing certificates carry emailProtection or the document-signing EKU,
		// never server auth, so the strict default would reject every one of them.
		AllowedEKUs: []x509.ExtKeyUsage{
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageAny,
		},
		TrustedRoots:                  v.Roots,
		SkipRevocationCheck:           !v.CheckRevocation,
		EnableExternalRevocationCheck: v.CheckRevocation,
		// Never trust the signer's own clock: it is the attack this tool exists
		// to detect. Only an RFC 3161 token proves when the signature existed.
		// This flag also selects the instant the *chain* is checked at, so a
		// verified token extends the validity window to the moment of signing.
		TrustSignatureTime:            true,
		ValidateTimestampCertificates: true,
		HTTPTimeout:                   10 * time.Second,
		// A caller-supplied clock wins over the wall clock, so tests and the
		// future "verify as of" mode can pin the instant.
		AtTime: v.Now,
	}

	response, err := verify.VerifyFileWithOptions(file, options)
	if err != nil {
		return nil, fmt.Errorf("verify %q: %w", path, err)
	}
	if response == nil {
		return nil, fmt.Errorf("verify %q: the verifier returned nothing", path)
	}

	reports := make([]domain.SignerReport, 0, len(response.Signers))
	for index := range response.Signers {
		// A pointer is needed because describeChain reads nested fields; taking
		// one per iteration keeps the copies local to this loop.
		signer := &response.Signers[index]
		reports = append(reports, v.translate(signer, index))
	}
	return reports, nil
}

// translate maps one library signer onto the domain report.
func (v *PDFVerifier) translate(signer *verify.Signer, index int) domain.SignerReport {
	report := domain.SignerReport{
		FieldName: signer.Name,
		Format:    "PAdES",
	}
	if report.FieldName == "" {
		report.FieldName = fmt.Sprintf("signature-%d", index+1)
	}

	// Integrity is a single fact: the signed byte ranges still hash correctly.
	if signer.ValidSignature {
		report.Integrity = domain.StatusGood
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.intact",
			Status:  domain.StatusGood,
			Message: "the signed content is unaltered",
		})
	} else {
		report.Integrity = domain.StatusBad
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.modified",
			Status:  domain.StatusBad,
			Message: "the document changed after it was signed",
		})
	}

	if len(signer.Certificates) > 0 {
		describeCertificate(signer.Certificates[0].Certificate, &report)
	}

	v.describeTime(signer, &report)
	v.describeChain(signer, &report)

	report.Trust = v.trustLevel(signer, report)
	return report
}

// describeTime decides which moment the certificate must be valid at.
//
// A trusted timestamp is authoritative. Without one the claimed signing time is
// used but flagged, because the signer controls it.
func (v *PDFVerifier) describeTime(signer *verify.Signer, report *domain.SignerReport) {
	verified, ok := trustedInstant(signer)
	if ok {
		report.SignedAt = verified
		report.Timestamped = true
		if signer.TimeStamp != nil && len(signer.TimeStamp.Certificates) > 0 {
			report.TimestampAuthority = signer.TimeStamp.Certificates[0].Subject.CommonName
		}
		return
	}

	if signer.SignatureTime != nil {
		report.SignedAt = *signer.SignatureTime
	}
	if signer.TimestampStatus == "invalid" {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the timestamp token is present but does not verify",
		})
	}
}

// trustedInstant returns the timestamp when it is present and verifies.
func trustedInstant(signer *verify.Signer) (time.Time, bool) {
	if signer.TimeStamp == nil || !signer.TimestampTrusted {
		return time.Time{}, false
	}
	if signer.TimestampStatus != "valid" {
		return time.Time{}, false
	}
	return signer.TimeStamp.Time, true
}

// describeChain reports what is known about the issuer and revocation.
func (v *PDFVerifier) describeChain(signer *verify.Signer, report *domain.SignerReport) {
	if len(signer.Certificates) == 0 || signer.Certificates[0].Certificate == nil {
		report.CertificateStatus = domain.StatusUnknown
		// A corrupted signature cannot be parsed, so the absence of a certificate
		// is a symptom, not a separate finding. Reporting both would bury the
		// real cause under noise.
		if signer.ValidSignature {
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "certificate.missing",
				Status:  domain.StatusUnknown,
				Message: "the signature does not embed the signing certificate",
			})
		}
		return
	}

	entry := signer.Certificates[0]
	// The certificates travel with the report so a revocation query can be built
	// for this certificate against its issuer.
	report.Revocation.Certificate = entry.Certificate
	report.Revocation.Issuer = issuerOf(signer, entry.Certificate)
	report.Revoked = signer.RevokedCertificate || entry.RevokedBeforeSigning
	if entry.RevocationTime != nil {
		report.RevokedAt = *entry.RevocationTime
	}

	switch {
	case report.SelfSigned:
		report.CertificateStatus = domain.StatusWarn
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "certificate.self_signed",
			Status:  domain.StatusWarn,
			Message: "the certificate is self-signed: valid cryptography, no third-party trust",
		})
	case signer.TrustedIssuer:
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
			Detail:  entry.VerifyError,
		})
	}

	if entry.RevocationTime != nil {
		report.RevokedAt = *entry.RevocationTime
	}
	if signer.RevokedCertificate || entry.RevokedBeforeSigning {
		code := "certificate.revoked_after_signing"
		status := domain.StatusWarn
		message := "the certificate was revoked after signing; the signature itself is unaffected"
		if entry.RevokedBeforeSigning {
			code = "certificate.revoked_before_signing"
			status = domain.StatusBad
			message = "the certificate was revoked before the signature was made"
		}
		report.Findings = append(report.Findings, domain.Finding{
			Code:    code,
			Status:  status,
			Message: message,
			Detail:  formatMoment(report.RevokedAt),
		})
	}
	for _, warning := range signer.Warnings {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "verification.warning",
			Status:  domain.StatusWarn,
			Message: warning.Error(),
		})
	}
}

// issuerOf finds the certificate that signed the leaf, among those the document
// carries. Without it an OCSP request cannot be built, and the report says so
// rather than guessing.
func issuerOf(signer *verify.Signer, leaf *x509.Certificate) *x509.Certificate {
	if signer == nil || leaf == nil {
		return nil
	}
	for _, candidate := range signer.Certificates {
		if candidate.Certificate == nil || candidate.Certificate.Equal(leaf) {
			continue
		}
		if bytes.Equal(candidate.Certificate.RawSubject, leaf.RawIssuer) {
			return candidate.Certificate
		}
	}
	return nil
}

// formatMoment renders an instant for a report detail, or empty when unset.
func formatMoment(moment time.Time) string {
	if moment.IsZero() {
		return ""
	}
	return moment.UTC().Format(time.RFC3339)
}

// trustLevel reduces everything known into one judgement.
func (v *PDFVerifier) trustLevel(signer *verify.Signer, report domain.SignerReport) domain.TrustLevel {
	if !signer.ValidSignature {
		return domain.TrustBroken
	}
	if signer.RevokedCertificate {
		return domain.TrustBroken
	}
	// A self-signed certificate proves nothing beyond "whoever holds this key
	// made this signature". It is not advanced, because no third party vouches
	// for the identity; calling it advanced would overstate the evidence.
	if report.SelfSigned {
		return domain.TrustUntrusted
	}
	if !signer.TrustedIssuer {
		return domain.TrustUntrusted
	}
	return domain.TrustAdvanced
}

// compile-time check.
var _ SignatureExtractor = (*PDFVerifier)(nil)
