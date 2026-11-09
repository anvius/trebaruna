package infrastructure

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/publickey"
	"codeberg.org/simplicer/trebaruna/src/verification/application"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
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
	// Anchors are the raw certificates the trust list published.
	//
	// The pool alone is not enough: the library chains each document certificate
	// against TrustedRoots and offers no way to supply intermediates, so a
	// document carrying only its leaf — what most Spanish and Italian tools
	// produce — never reaches the CA. The raw certificates let this adapter add
	// them to the roots pool, which is the only place the library looks.
	Anchors []*x509.Certificate
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

// WithAnchorCertificates also keeps the raw certificates.
//
// It exists because a pool cannot be enumerated, and the PDF library only accepts
// a roots pool: without the certificates themselves there is no way to make an
// issuer reachable when the document does not carry its chain.
func (v *PDFVerifier) WithAnchorCertificates(roots, intermediates *x509.CertPool, anchors []*x509.Certificate) application.DocumentExtractor {
	clone := v.WithAnchors(roots, intermediates).(*PDFVerifier)
	publickey.Complete(anchors...)
	clone.Anchors = anchors
	return clone
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

	// The library chains each document certificate against TrustedRoots, using the
	// document's own certificates as intermediates. A PDF that carries only the
	// leaf — which is what most Spanish and Italian signing tools produce — cannot
	// chain against the CA alone: the issuer has to be reachable from the roots
	// pool, so the trust-list certificates are merged into it here.
	roots := v.rootsWithAnchors()

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
		AllowedEKUs:                   allowedDocumentEKUs,
		TrustedRoots:                  roots,
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

	envelopes := signatureEnvelopes(path)
	checkedHere := map[int]bool{}
	reports := make([]domain.SignerReport, 0, len(response.Signers))
	for index := range response.Signers {
		// A pointer is needed because describeChain reads nested fields; taking
		// one per iteration keeps the copies local to this loop.
		signer := &response.Signers[index]
		if report, ok := v.checkHere(path, signer, index, envelopes, checkedHere); ok {
			reports = append(reports, report)
			continue
		}
		report := v.translate(signer, index)
		bindPDFCertificate(envelopes, signer, &report)
		if report.Integrity == domain.StatusBad {
			report.Trust = domain.TrustBroken
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// checkHere verifies a signature the PDF library does not implement
// (RSASSA-PSS) with the CAdES checks: a PDF signature is a detached CMS over
// its byte ranges. Its envelope is the unchecked one with the same /Name.
// The revocation data of the document's /DSS is not read for it.
func (v *PDFVerifier) checkHere(path string, signer *verify.Signer, index int, envelopes []pdfEnvelope, taken map[int]bool) (domain.SignerReport, bool) {
	if signer.ValidSignature || !libraryCannotCheck(signer) {
		return domain.SignerReport{}, false
	}
	for candidate, envelope := range envelopes {
		if taken[candidate] || envelope.name != signer.Name || len(envelope.tree.signers) != 1 ||
			!isPSS(envelope.tree.signers[0].SignatureAlgorithm) {
			continue
		}
		taken[candidate] = true
		signed, err := envelope.signedBytes(path)
		if err != nil {
			return domain.SignerReport{}, false
		}
		cades := &CadesVerifier{Roots: v.Roots, Now: v.Now, Anchors: v.Anchors}
		reports, err := cades.envelopeReports(envelope.der, signed)
		if err != nil || len(reports) != 1 {
			return domain.SignerReport{}, false
		}
		report := reports[0]
		report.FieldName, report.Format = fieldName(signer, index), "PAdES"
		report.Declared.Place = signer.Location
		return report, true
	}
	return domain.SignerReport{}, false
}

// libraryCannotCheck reports a signature the PDF library left unverified
// for want of an algorithm, not because it does not match.
func libraryCannotCheck(signer *verify.Signer) bool {
	for _, problem := range signer.ValidationErrors {
		if unsupportedByLibrary(problem) {
			return true
		}
	}
	return false
}

// fieldName is how a report names a PDF signature.
func fieldName(signer *verify.Signer, index int) string {
	if signer.Name == "" {
		return fmt.Sprintf("signature-%d", index+1)
	}
	return signer.Name
}

// translate maps one library signer onto the domain report.
func (v *PDFVerifier) translate(signer *verify.Signer, index int) domain.SignerReport {
	report := domain.SignerReport{
		FieldName: fieldName(signer, index),
		Format:    "PAdES",
	}

	// Integrity is a single fact: the signed byte ranges still hash correctly.
	switch {
	case signer.ValidSignature:
		report.Integrity = domain.StatusGood
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.intact",
			Status:  domain.StatusGood,
			Message: "the signed content is unaltered",
		})
	case libraryCannotCheck(signer):
		report.Integrity = domain.StatusUnknown
		report.Findings = append(report.Findings, unverifiableFinding(errors.Join(signer.ValidationErrors...)))
	default:
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

	// The library chains with Go's default key usages, which is ServerAuth, and
	// that rejects every document-signing certificate: they carry e-mail
	// protection or client authentication, never server auth. Its VerifyOptions
	// exposes no way to override this, so the chain is re-checked here with Any
	// when the library says the issuer is unknown.
	trustedIssuer := signer.TrustedIssuer
	if !trustedIssuer && !report.SelfSigned {
		if v.chainTrusts(entry.Certificate, signer) {
			trustedIssuer = true
			report.Findings = append(report.Findings, domain.Finding{
				Code:   "verification.warning",
				Status: domain.StatusWarn,
				Message: "the issuer chains to the trust list, but the library's own " +
					"check rejected the certificate's key usage",
				Detail: "ServerAuth is Go's default and document certificates never carry it",
			})
		}
	}

	switch {
	case report.SelfSigned:
		report.CertificateStatus = domain.StatusWarn
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "certificate.self_signed",
			Status:  domain.StatusWarn,
			Message: "the certificate is self-signed: valid cryptography, no third-party trust",
		})
	case trustedIssuer:
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
		// Revoked before signing means the signer was not entitled to sign, not
		// that the document was altered.
		return domain.TrustInvalid
	}
	// A self-signed certificate proves nothing beyond "whoever holds this key
	// made this signature". It is not advanced, because no third party vouches
	// for the identity; calling it advanced would overstate the evidence.
	if report.SelfSigned {
		return domain.TrustUntrusted
	}
	// The report already carries the answer: describeChain re-checks the chain when
	// the library's key-usage default rejects a document certificate, so
	// signer.TrustedIssuer alone would undo that correction here.
	if report.CertificateStatus != domain.StatusGood {
		return domain.TrustUntrusted
	}
	return domain.TrustAdvanced
}

// compile-time check.
var _ SignatureExtractor = (*PDFVerifier)(nil)

// rootsWithAnchors returns the pool the library chains against.
//
// Every trust-list certificate is added as a root, self-signed or not. That is
// what makes a leaf-only document chain: the library verifies with
// Roots = TrustedRoots and Intermediates = the document's own certificates, so an
// issuer that is not in the document must be present in Roots to be found.
//
// Adding a subordinate CA as a root is a deliberate trade: the list published it
// as a qualified anchor for issuing qualified certificates, so trusting it
// directly is trusting the list's own statement. The alternative — never chaining
// a leaf-only signature — would make every qualified Spanish and Italian
// signature unverifiable.
func (v *PDFVerifier) rootsWithAnchors() *x509.CertPool {
	if len(v.Anchors) == 0 {
		if v.Roots != nil {
			return v.Roots
		}
		return v.Intermediates
	}

	pool := x509.NewCertPool()
	for _, certificate := range v.Anchors {
		pool.AddCert(certificate)
	}
	// System roots stay available so a document from a public CA that is not in
	// the national list still verifies.
	if v.Roots != nil {
		for _, certificate := range v.Anchors {
			v.Roots.AddCert(certificate)
		}
		return v.Roots
	}
	return pool
}

// allowedDocumentEKUs are the purposes a document-signing certificate may carry.
//
// The list is longer than it looks like it should be because "the" document
// signing purpose does not exist in practice: European qualified CAs issue
// e-mail protection, Spanish notarial and corporate certificates carry client
// authentication, and private PKI often omits EKU entirely. Restricting this list
// rejects real, valid signatures — it did, for a Spanish notarial certificate
// whose only purposes were client authentication and e-mail protection.
var allowedDocumentEKUs = []x509.ExtKeyUsage{
	x509.ExtKeyUsageEmailProtection,
	x509.ExtKeyUsageClientAuth,
	x509.ExtKeyUsageCodeSigning,
	x509.ExtKeyUsageAny,
}

// chainTrusts re-verifies the chain with the key usages a document certificate
// actually carries.
//
// Every certificate the signature embeds is offered as an intermediate, and the
// anchors from the trust list are the roots. KeyUsages is Any because the purpose
// of a signing certificate is decided by the profile it was issued under, not by
// Go's ServerAuth default.
func (v *PDFVerifier) chainTrusts(leaf *x509.Certificate, signer *verify.Signer) bool {
	if leaf == nil || v.Roots == nil && v.Intermediates == nil {
		return false
	}

	intermediates := x509.NewCertPool()
	for _, embedded := range signer.Certificates {
		if embedded.Certificate == nil || embedded.Certificate.Equal(leaf) {
			continue
		}
		publickey.Complete(embedded.Certificate)
		intermediates.AddCert(embedded.Certificate)
	}

	roots := v.rootsWithAnchors()
	if roots == nil {
		return false
	}

	at := v.Now
	if at.IsZero() {
		at = time.Now()
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}
