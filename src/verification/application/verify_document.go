// Package application orchestrates verification.
package application

import (
	"context"
	"crypto/x509"
	"strings"
	"time"

	trustdomain "codeberg.org/anvius/trebaruna/src/trust/domain"
	verification "codeberg.org/anvius/trebaruna/src/verification/domain"
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

// CertificateAware is implemented by extractors that can also take the raw
// anchor certificates.
//
// A pool cannot be enumerated, and the PDF library accepts only a roots pool, so
// an extractor that needs to make an issuer reachable must receive the
// certificates themselves.
type CertificateAware interface {
	WithAnchorCertificates(roots, intermediates *x509.CertPool, anchors []*x509.Certificate) DocumentExtractor
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

// RevocationChecker asks a responder whether a certificate is revoked.
//
// It is an interface so the use case can run offline, and so tests can assert
// that a verification which was not asked to reach the network never does.
type RevocationChecker interface {
	Check(ctx context.Context, certificate, issuer *x509.Certificate) verification.Revocation
}

// VerifyDocument is the use case behind `trebaruna verify`.
type VerifyDocument struct {
	pdf   DocumentExtractor
	cades DocumentExtractor
	xades DocumentExtractor
	trust TrustProvider
	clock Clock
	// revocation is nil until the caller asks for a network check.
	revocation RevocationChecker
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

// WithRevocation enables status checks.
//
// Passing nil keeps verification offline, which is the default: a tool that
// contacts a third party without being asked tells that third party which
// documents its user opens.
func (u *VerifyDocument) WithRevocation(checker RevocationChecker) *VerifyDocument {
	u.revocation = checker
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
		if aware, ok := extractor.(CertificateAware); ok {
			extractor = aware.WithAnchorCertificates(
				anchors.roots, anchors.intermediates, list.QualifiedAnchors())
		} else if aware, ok := extractor.(AnchorAware); ok {
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
			Message: "the trust list is past its nextUpdate: run 'trebaruna trust sync'",
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

	// A signature made by someone who was not entitled to sign at that
	// moment — the certificate had expired, was revoked, or had not started —
	// is invalid, not tampered. Integrity can be perfect and the signature still
	// carries no legal force, which is what TrustInvalid records.
	if signer.Integrity == verification.StatusBad {
		signer.Trust = verification.TrustBroken
		return signer
	}
	if validity.ExpiredAtSigning() {
		signer.Trust = verification.TrustInvalid
		return signer
	}

	if signer.CertificateStatus == verification.StatusGood {
		signer.CertificateStatus = status
	}

	u.evaluateRevocation(&signer)
	u.evaluateTimestamp(&signer, list)
	u.evaluateQualification(&signer, list)

	return signer
}

// evaluateRevocation asks a responder, when one is configured.
//
// The result is recorded even when it is "unknown": silence about a check that
// did not happen is how a report implies a certificate is fine when nobody
// looked. A signature made before the revocation survives it, so only a
// revocation that predates the signature is fatal.
func (u *VerifyDocument) evaluateRevocation(signer *verification.SignerReport) {
	if u.revocation == nil {
		return
	}

	evidence := &signer.Revocation
	if evidence.Certificate == nil {
		evidence.Status = verification.Revocation{
			Status:    verification.RevocationUnknown,
			Reason:    "the signature does not embed the certificate to check",
			CheckedAt: u.clock.Now(),
		}
		return
	}

	evidence.Status = u.revocation.Check(context.Background(), evidence.Certificate, evidence.Issuer)
	evidence.Checked = evidence.Status.WasChecked()
	signer.Revoked = evidence.Status.IsRevoked()
	if signer.Revoked {
		signer.RevokedAt = evidence.Status.RevokedAt
	}

	switch {
	case evidence.Status.FatalAtSigning(signer.SignedAt):
		signer.Findings = append(signer.Findings, verification.Finding{
			Code:    "certificate.revoked_before_signing",
			Status:  verification.StatusBad,
			Message: "the certificate was revoked before the signature was made",
			Detail:  formatRevocationMoment(evidence.Status.RevokedAt),
		})
		signer.Revoked = true
		// The signer was not entitled to sign when they did. The document may be
		// perfectly intact; the signature still has no force.
		signer.Trust = verification.TrustInvalid
	case signer.Revoked:
		signer.Findings = append(signer.Findings, verification.Finding{
			Code:    "certificate.revoked_after_signing",
			Status:  verification.StatusWarn,
			Message: "the certificate was revoked after signing; the signature itself is unaffected",
			Detail:  formatRevocationMoment(evidence.Status.RevokedAt),
		})
	case evidence.Checked:
		signer.Findings = append(signer.Findings, verification.Finding{
			Code:    "certificate.not_revoked",
			Status:  verification.StatusGood,
			Message: "a responder confirmed the certificate is not revoked",
			Detail:  evidence.Status.Source,
		})
	default:
		// Not an error about the certificate: an error about our knowledge.
		signer.Findings = append(signer.Findings, verification.Finding{
			Code:    "certificate.revocation_unchecked",
			Status:  verification.StatusWarn,
			Message: "the certificate revocation status could not be obtained",
			Detail:  evidence.Status.Reason,
		})
	}
}

// formatRevocationMoment renders a date for a finding.
func formatRevocationMoment(moment time.Time) string {
	if moment.IsZero() {
		return ""
	}
	return moment.UTC().Format(time.RFC3339)
}

// evaluateTimestamp decides whether the authority behind a timestamp is proven.
//
// Three facts are independent and all are required:
//
//	bound    the imprint matches this signature's own value (checked earlier)
//	usage    the timestamp certificate carries id-kp-timeStamping
//	listed   a granted TSA/QTST in an authenticated list can issue that chain
//
// States differ in what they publish: some list the authority's CA, others the
// end-entity certificate of the time-stamping unit. Both are accepted, because
// the list is the authority stating which certificates it operates, and matching
// either is the same claim.
func (u *VerifyDocument) evaluateTimestamp(signer *verification.SignerReport, list trustdomain.TrustList) {
	evidence := &signer.TimestampEvidence
	if !evidence.Bound {
		return
	}

	// The token's own time is the reference for the grant comparison: a service
	// approved after the seal was made cannot have issued it.
	at := signer.SignedAt

	if list.Authenticated {
		if service, found := timestampService(list, evidence); found {
			evidence.ServiceListed = true
			evidence.ProviderName = service.ProviderName
			evidence.ServiceName = service.ServiceName
			evidence.GrantedSince = service.StatusSince
		}
	}

	// Accredited requires the listed service and the key usage. The date check
	// lives in the same place so a token made before its authority was granted
	// cannot pass.
	evidence.Accredited = evidence.ServiceListed && evidence.CertificateCanTimestamp
	if evidence.Accredited && !evidence.GrantedSince.IsZero() {
		if at.IsZero() || at.Before(evidence.GrantedSince) {
			evidence.Accredited = false
		}
	}

	if evidence.Accredited {
		signer.Findings = append(signer.Findings, verification.Finding{
			Code:    "timestamp.accredited",
			Status:  verification.StatusGood,
			Message: "the timestamp authority is a qualified service of an authenticated trust list",
			Detail:  evidence.ProviderName,
		})
		return
	}

	signer.Findings = append(signer.Findings, verification.Finding{
		Code:    "timestamp.untrusted_authority",
		Status:  verification.StatusWarn,
		Message: "the timestamp is bound but its authority is not proven qualified",
		Detail:  missingTimestampReasons(*evidence, at),
	})
}

// timestampService finds the granted qualified time-stamping service that covers
// the token's certificate.
//
// The exact certificate is tried first, and the order is measured, not stylistic:
// across the 18 authenticated lists, 227 of 231 granted TSA/QTST services publish
// the time-stamping unit's own certificate while only 60 can be reached through
// their issuer. Searching by issuer first would leave 167 qualified authorities
// unproven, which is the difference between an advance and a decoration.
func timestampService(list trustdomain.TrustList, evidence *verification.TimestampEvidence) (trustdomain.TrustService, bool) {
	if services := list.TimestampServiceForCertificate(evidence.Certificate); len(services) > 0 {
		return services[0], true
	}
	if evidence.CertificateIssuerDN != "" {
		if services := list.TimestampServicesFor(evidence.CertificateIssuerDN); len(services) > 0 {
			return services[0], true
		}
	}
	return trustdomain.TrustService{}, false
}

// missingTimestampReasons spells out what keeps a timestamp from being accredited.
func missingTimestampReasons(evidence verification.TimestampEvidence, at time.Time) string {
	var missing []string
	if !evidence.CertificateCanTimestamp {
		missing = append(missing, "the timestamp certificate lacks id-kp-timeStamping")
	}
	if !evidence.ServiceListed {
		missing = append(missing, "no granted TSA/QTST in the authenticated trust list issued it")
	}
	if !evidence.GrantedSince.IsZero() {
		switch {
		case at.IsZero():
			missing = append(missing, "the token time is unknown, so the grant cannot be checked")
		case at.Before(evidence.GrantedSince):
			missing = append(missing, "the authority was not granted yet when the token was issued")
		}
	}
	return strings.Join(missing, "; ")
}

// evaluateQualification decides whether a signature can be called qualified.
//
// eIDAS sets three independent conditions, and all of them must hold:
//
//	certificate  a qualified certificate, proven by QcCompliance
//	device       the private key lived in a QSCD, proven by QcSSCD or by the
//	             QCWithQSCD qualifier the list publishes for the service
//	issuer       a CA/QC that is granted now and was granted at signing time,
//	             in a list authenticated against the EU root
//
// Anything less stays advanced. Overstating a signature is the one error this
// tool cannot afford: a user asked to trust a document, and "qualified" is the
// strongest claim the law recognises.
func (u *VerifyDocument) evaluateQualification(signer *verification.SignerReport, list trustdomain.TrustList) {
	evidence := verification.Qualification{
		CertificateQualified: signer.Claims.Compliant,
		DeviceQualified:      signer.Claims.DeviceQualified,
	}
	if evidence.DeviceQualified {
		evidence.DeviceSource = "certificate claims QcSSCD"
	}

	// A certificate that publishes a QcType and excludes signatures is a
	// qualified certificate for something else: a seal, a website. When the
	// statement is absent the certificate says nothing, which is not the same as
	// saying "not a signer".
	if signer.Claims.TypeDeclared && !signer.Claims.SignatureType {
		evidence.DeclaredSealOnly = true
	}

	// The service half needs an authenticated list. Inventory from a downloaded
	// file grants nothing, however convincing its names look.
	if list.Authenticated {
		if service, found := matchingService(list, signer.IssuerDN, signer.SignedAt); found {
			evidence.ServiceListed = true
			evidence.ServiceProvider = service.ProviderName
			evidence.ServiceName = service.ServiceName
			evidence.ServiceGrantedSince = service.StatusSince
			if !evidence.DeviceQualified && service.HasQualifier("QCWithQSCD") {
				evidence.DeviceQualified = true
				evidence.DeviceSource = "the trust list publishes QCWithQSCD for the issuing service"
			}
		}
	}

	signer.Qualification = evidence
	signer.Qualified = evidence.IsQualified(signer.SignedAt)

	at := signer.SignedAt
	// Only an advanced, currently-sound signature can be promoted. A broken or
	// untrusted one is already below advanced and "qualified" would contradict
	// the findings above it.
	if signer.Qualified && !evidence.DeclaredSealOnly && signer.Trust == verification.TrustAdvanced {
		signer.Trust = verification.TrustQualified
		signer.Findings = append(signer.Findings, verification.Finding{
			Code:    "signature.qualified",
			Status:  verification.StatusGood,
			Message: "the signature is qualified: qualified certificate, qualified device and a listed qualified issuer",
			Detail:  evidence.ServiceProvider,
		})
		return
	}

	// Not qualified: say why. A verdict without its reason is a verdict the
	// user cannot challenge or fix.
	missing := evidence.Missing(at)
	if len(missing) > 0 && signer.Trust == verification.TrustAdvanced {
		signer.Findings = append(signer.Findings, verification.Finding{
			Code:    "signature.not_qualified",
			Status:  verification.StatusWarn,
			Message: "the signature is advanced but not qualified",
			Detail:  strings.Join(missing, "; "),
		})
	}
}

// matchingService finds the granted qualified CA whose certificate issued this
// chain. The service must have been granted before the signature was made: a
// CA approved last year cannot have issued a document five years ago.
func matchingService(list trustdomain.TrustList, issuerDN string, signedAt time.Time) (trustdomain.TrustService, bool) {
	for _, service := range list.QualifiedServicesFor(issuerDN) {
		if !service.StatusSince.IsZero() && !signedAt.IsZero() && signedAt.Before(service.StatusSince) {
			continue
		}
		return service, true
	}
	return trustdomain.TrustService{}, false
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
