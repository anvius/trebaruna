// Package application orchestrates verification.
package application

import (
	"crypto/x509"
	"time"

	trustdomain "codeberg.org/simplicer/firma-it/src/trust/domain"
	verification "codeberg.org/simplicer/firma-it/src/verification/domain"
)

// DocumentExtractor reads the signatures of one document.
type DocumentExtractor interface {
	Extract(path string) ([]verification.SignerReport, error)
}

// AnchorAware is implemented by extractors that can validate a chain against a
// pool built from a trust list.
//
// Without it, the PDF verifier falls back to the operating system roots, which
// do not contain the qualified CAs that issue document-signing certificates:
// they would report every Italian or Belgian qualified signature as untrusted.
type AnchorAware interface {
	WithAnchors(roots, intermediates *x509.CertPool) DocumentExtractor
}

// TrustProvider supplies the trust list for a territory.
//
// It returns an empty list rather than an error when no list is cached: a
// verification must still report integrity, even offline and without a TSL.
type TrustProvider interface {
	Load(territory string) (trustdomain.TrustList, error)
}

// Clock reports the current time, injected for tests.
type Clock interface {
	Now() time.Time
}

// VerifyDocument is the use case behind `firma-it verify`.
type VerifyDocument struct {
	pdf   DocumentExtractor
	cades DocumentExtractor
	xades DocumentExtractor
	trust TrustProvider
	clock Clock
}

// NewVerifyDocument wires the use case.
func NewVerifyDocument(pdf, cades DocumentExtractor, trust TrustProvider, clock Clock) *VerifyDocument {
	return &VerifyDocument{pdf: pdf, cades: cades, trust: trust, clock: clock}
}

// WithXades attaches the XML verifier, which is optional so a caller that only
// checks PDFs does not need a XAdES implementation.
func (u *VerifyDocument) WithXades(xades DocumentExtractor) *VerifyDocument {
	u.xades = xades
	return u
}

// Request is one verification.
type Request struct {
	// Path is the document to verify.
	Path string
	// Format is "pdf", "cades" or "xades". Empty means "detect from the suffix".
	Format string
	// Territory selects the trust list, e.g. "IT" or "ES".
	Territory string
}

// Execute verifies and returns the report.
func (u *VerifyDocument) Execute(request Request) (verification.DocumentReport, error) {
	now := u.clock.Now()

	report := verification.DocumentReport{
		Path:       request.Path,
		VerifiedAt: now,
	}

	format := detectFormat(request.Path, request.Format)
	report.Format = format

	extractor := u.extractorFor(format)
	if extractor == nil {
		report.Warnings = append(report.Warnings, verification.Finding{
			Code:    "format.unsupported",
			Status:  verification.StatusUnknown,
			Message: "no verifier is available for this format",
			Detail:  format,
		})
		return report, nil
	}

	list, trustWarning := u.loadTrust(request.Territory, now)
	if trustWarning != nil {
		report.Warnings = append(report.Warnings, *trustWarning)
	}

	// A trust list is only usable as anchors when it parses; an empty list means
	// "no anchors", and the extractor then falls back to the system roots.
	// Cached lists are inventory until authenticated against pinned publication
	// keys. Their contents must never grant trust to a document.
	if anchors := anchorPool(list); anchors != nil {
		if aware, ok := extractor.(AnchorAware); ok {
			extractor = aware.WithAnchors(anchors.roots, anchors.intermediates)
		}
	}

	signers, err := extractor.Extract(request.Path)
	if err != nil {
		return report, err
	}

	for index := range signers {
		signers[index] = u.evaluateSigner(signers[index], now, list)
	}

	report.Signers = signers
	report.Signed = len(signers) > 0
	report.Trust = report.Verdict()
	return report, nil
}

// anchorSet groups the pools built from a trust list.
type anchorSet struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

// anchorPool builds trust anchors from the qualified services of a list.
//
// It returns nil when the list has no usable anchors, so callers can tell
// "nothing to add" apart from "an empty pool that would reject everything".
func anchorPool(list trustdomain.TrustList) *anchorSet {
	if !list.Authenticated || list.QualifiedCount() == 0 {
		return nil
	}

	roots, intermediates, added := list.AnchorPool()
	if added == 0 {
		return nil
	}
	return &anchorSet{roots: roots, intermediates: intermediates}
}

// extractorFor picks the adapter for a format.
func (u *VerifyDocument) extractorFor(format string) DocumentExtractor {
	switch format {
	case "pdf":
		return u.pdf
	case "cades":
		return u.cades
	case "xades":
		return u.xades
	}
	return nil
}

// loadTrust reads the list, degrading to a warning.
func (u *VerifyDocument) loadTrust(territory string, now time.Time) (trustdomain.TrustList, *verification.Finding) {
	if u.trust == nil {
		return trustdomain.TrustList{}, nil
	}

	list, err := u.trust.Load(territory)
	if err != nil {
		return trustdomain.TrustList{}, &verification.Finding{
			Code:    "trustlist.unavailable",
			Status:  verification.StatusWarn,
			Message: "no trust list available: issuer verdicts are limited to the system roots",
			Detail:  err.Error(),
		}
	}

	if !list.Fresh(now) {
		return list, &verification.Finding{
			Code:    "trustlist.stale",
			Status:  verification.StatusWarn,
			Message: "the trust list is past its nextUpdate: run 'firma-it trust sync'",
			Detail:  list.NextUpdate.UTC().Format(time.RFC3339),
		}
	}
	return list, nil
}

// evaluateSigner adds the validity checks the extractor could not do alone.
func (u *VerifyDocument) evaluateSigner(
	signer verification.SignerReport,
	now time.Time,
	list trustdomain.TrustList,
) verification.SignerReport {
	validity := verification.Validity{
		NotBefore: signer.NotBefore,
		NotAfter:  signer.NotAfter,
		AtSigning: signer.SignedAt,
		// Only a verified RFC 3161 token makes the moment trustworthy.
		HasTrustedTime: signer.Timestamped,
		Now:            now,
		RevokedAt:      signer.RevokedAt,
	}

	status, findings := validity.Evaluate()
	signer.ExpiredAtSigning = validity.ExpiredAtSigning()
	signer.ExpiredNow = validity.ExpiredNow()
	signer.Findings = append(signer.Findings, findings...)

	// A broken signature or an expired-at-signing certificate is fatal regardless
	// of what else passed: one bad fact spoils the whole verdict.
	if signer.Integrity == verification.StatusBad || validity.ExpiredAtSigning() {
		signer.Trust = verification.TrustBroken
		return signer
	}

	if signer.CertificateStatus == verification.StatusGood {
		signer.CertificateStatus = status
	}

	// Downloaded TSL XML is inventory, not a trust anchor. Neither an issuer
	// name match nor a timestamp proves QES qualification. Until LOTL/TSL
	// signatures, service history and certificate qualifiers are validated,
	// never upgrade a verdict from that inventory.

	return signer
}

// detectFormat infers the container from the suffix.
func detectFormat(path, explicit string) string {
	if explicit != "" {
		return explicit
	}
	switch {
	case hasSuffix(path, ".p7m"), hasSuffix(path, ".p7s"):
		return "cades"
	case hasSuffix(path, ".pdf"):
		return "pdf"
	case hasSuffix(path, ".xml"), hasSuffix(path, ".xsig"):
		return "xades"
	}
	return "unknown"
}

// hasSuffix compares case-insensitively.
func hasSuffix(value, suffix string) bool {
	if len(value) < len(suffix) {
		return false
	}
	tail := value[len(value)-len(suffix):]
	for index := 0; index < len(suffix); index++ {
		left, right := tail[index], suffix[index]
		if 'A' <= left && left <= 'Z' {
			left += 'a' - 'A'
		}
		if 'A' <= right && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
	}
	return true
}
