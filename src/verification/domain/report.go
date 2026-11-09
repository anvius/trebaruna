// Package domain defines what a verification report says, in business terms.
//
// It separates three questions that non-experts constantly merge:
//
//	integrity  did the bytes change after signing?
//	trust      is the issuer one we recognise?
//	validity   was the certificate usable at signing time?
//
// A signature can be cryptographically intact and still worthless: expired,
// revoked, or issued by an authority nobody trusts. Reporting a single "valid"
// flag is how users end up trusting the wrong documents.
package domain

import (
	"crypto/x509"
	"fmt"
	"time"
)

// Status is the outcome of one check.
type Status string

const (
	// StatusGood means the check passed.
	StatusGood Status = "good"

	// StatusWarn means the check passed but needs attention.
	StatusWarn Status = "warn"

	// StatusBad means the check failed: do not trust this signature.
	StatusBad Status = "bad"

	// StatusUnknown means the check could not be performed.
	StatusUnknown Status = "unknown"

	// StatusNotApplicable means the check does not apply to this signature.
	StatusNotApplicable Status = "n/a"
)

// TrustLevel summarises how much a verification result can be relied on.
type TrustLevel string

const (
	// TrustQualified is a qualified signature from a trusted authority, valid
	// at signing time. This is what eIDAS calls a QES when the certificate is
	// qualified and the device is qualified too.
	TrustQualified TrustLevel = "qualified"

	// TrustAdvanced is a valid advanced signature from a trusted authority.
	TrustAdvanced TrustLevel = "advanced"

	// TrustUntrusted means the cryptography holds but the issuer is not known.
	TrustUntrusted TrustLevel = "untrusted"

	// TrustInvalid means the document itself is intact, but the signature was
	// made by someone who was not entitled to sign at that moment: the
	// certificate had expired, was not yet valid, or was already revoked. The
	// cryptography holds; the signature still has no legal force.
	//
	// This is not TrustBroken. TrustBroken is a claim that the document or the
	// signature was altered, which is a different and stronger accusation. Saying
	// "altered" here would be false, and in a legal signature tool a false
	// accusation of tampering is worse than no verdict at all.
	TrustInvalid TrustLevel = "invalid"

	// TrustBroken means the document or the signature was altered.
	TrustBroken TrustLevel = "broken"

	// TrustUnknown means the verifier could not decide.
	TrustUnknown TrustLevel = "unknown"
)

// Severity orders findings so the worst one can be shown first.
func (s Status) Severity() int {
	switch s {
	case StatusBad:
		return 3
	case StatusUnknown:
		return 2
	case StatusWarn:
		return 1
	case StatusGood:
		return 0
	}
	return 0
}

// Finding is one statement about one signature, with a machine-readable code.
//
// The code travels to the UI and the JSON output; the message is an English
// fallback for logs. Translations live in the messaging catalogue, so the same
// report can be shown in Italian, Spanish or English without re-running checks.
type Finding struct {
	// Code identifies the finding, e.g. "certificate.expired".
	Code string
	// Status is the severity of this particular statement.
	Status Status
	// Message is the English fallback.
	Message string
	// Detail carries values the message needs, such as a date.
	Detail string
}

// CertificateClaims are the qualification statements inside the certificate.
type CertificateClaims struct {
	// Recognised reports that the qcStatements extension was present and parsed.
	Recognised bool
	// Compliant reports the QcCompliance statement: a qualified certificate.
	Compliant bool
	// DeviceQualified reports the QcSSCD statement: the private key was held in
	// a secure signature-creation device. eIDAS calls the device QSCD; the
	// certificate statement still uses the older name.
	DeviceQualified bool
	// TypeDeclared reports whether the certificate published a QcType statement
	// at all. QcType is optional, so its absence means "says nothing", never
	// "is a seal".
	TypeDeclared bool
	// SignatureType reports a QcType entry for electronic signatures. A
	// certificate can instead declare itself for seals or web authentication.
	SignatureType bool
}

// Qualification is the evidence collected for a possible QES verdict.
//
// It is a report of what was checked, not a promise: missing evidence is listed
// verbatim so the user can see which condition failed.
type Qualification struct {
	// CertificateQualified reports the QcCompliance claim.
	CertificateQualified bool
	// DeviceQualified reports a qualified signature-creation device, from either
	// source: the QcSSCD statement or the QCWithQSCD qualifier of the service.
	DeviceQualified bool
	// DeviceSource records where the device fact came from.
	DeviceSource string
	// ServiceListed reports a granted CA/QC in the authenticated list that can
	// issue this chain.
	ServiceListed bool
	// ServiceProvider and ServiceName identify the matched service.
	ServiceProvider string
	ServiceName     string
	// ServiceGrantedSince is when the service entered its current status.
	ServiceGrantedSince time.Time
	// DeclaredSealOnly reports a certificate whose QcType excludes signatures.
	DeclaredSealOnly bool
}

// IsQualified reports whether every eIDAS condition held at the given moment.
//
// The signing moment matters: a service granted after the signature was made did
// not issue it, even if the same CA is listed today. When the moment is unknown
// and the list publishes a grant date, the comparison cannot be made, so the
// answer is "not proven" rather than "probably fine".
func (q Qualification) IsQualified(at time.Time) bool {
	if q.DeclaredSealOnly {
		return false
	}
	if !q.CertificateQualified || !q.DeviceQualified || !q.ServiceListed {
		return false
	}
	if !q.ServiceGrantedSince.IsZero() {
		if at.IsZero() || at.Before(q.ServiceGrantedSince) {
			return false
		}
	}
	return true
}

// Missing lists the conditions that are not satisfied.
//
// Returning the reasons instead of a boolean is deliberate: "not qualified" is
// useless to a user who wants to know what would make it qualified.
func (q Qualification) Missing(at time.Time) []string {
	var missing []string
	if !q.CertificateQualified {
		missing = append(missing, "the certificate carries no QcCompliance statement")
	}
	if !q.DeviceQualified {
		missing = append(missing, "the private key is not proven to live in a qualified device")
	}
	if !q.ServiceListed {
		missing = append(missing, "no granted CA/QC in the authenticated trust list issued this chain")
	}
	if !q.ServiceGrantedSince.IsZero() {
		switch {
		case at.IsZero():
			missing = append(missing, "the signing time is unknown, so the service grant cannot be checked against it")
		case at.Before(q.ServiceGrantedSince):
			missing = append(missing, "the issuing service was not granted yet when the signature was made")
		}
	}
	if q.DeclaredSealOnly {
		missing = append(missing, "the certificate is qualified for seals or web authentication, not for signatures")
	}
	return missing
}

// TimestampEvidence is what was checked about the authority that sealed a
// signature.
type TimestampEvidence struct {
	// Bound reports a token whose imprint matches this signature.
	Bound bool
	// CertificateCanTimestamp reports id-kp-timeStamping on the signer.
	CertificateCanTimestamp bool
	// ServiceListed reports a granted TSA/QTST in an authenticated list.
	ServiceListed bool
	// ProviderName and ServiceName identify the matched service.
	ProviderName string
	ServiceName  string
	// GrantedSince is when the service entered its current status.
	GrantedSince time.Time
	// Accredited reports whether every condition held at the token's own time.
	Accredited bool
	// CertificateIssuerDN is the subject of the CA that issued the timestamp
	// certificate, which is what a list publishing the authority's CA contains.
	CertificateIssuerDN string
	// Certificate is the timestamp certificate itself, for lists that publish
	// the end-entity unit instead of its issuer.
	Certificate *x509.Certificate
}

// RevocationEvidence carries the material a status check needs.
//
// The certificates travel with the report because a revocation query must be
// signed for one certificate against its issuer; without them the use case can
// only say the check was not possible.
type RevocationEvidence struct {
	// Certificate is the signing certificate.
	Certificate *x509.Certificate
	// Issuer is the certificate that signed it, when the document carries it.
	Issuer *x509.Certificate
	// Status is the outcome once a check has run.
	Status Revocation
	// Checked reports whether a responder was consulted at all.
	Checked bool
}

// SignerReport is everything known about one signature in the document.
type SignerReport struct {
	// FieldName is the signature field, e.g. "F38a".
	FieldName string
	// Countersigns names the signature this one counter-signs, when it is a
	// counter-signature; empty for a signature over the document.
	Countersigns string
	// Declared is what the signature says of itself in what it signs: the
	// policy it follows, the roles its signer claims, where it was made.
	Declared Declarations
	// SignerName is the subject common name.
	SignerName string
	// Identifier is the national identifier from the certificate.
	Identifier string
	// Issuer is the CA that issued the certificate.
	Issuer string
	// IssuerDN is the issuer's distinguished name as printed by the CA.
	// The trust list publishes CA subjects, so this is what makes a precise
	// match possible instead of comparing a display name.
	IssuerDN string
	// Claims are the qualification statements the certificate itself carries.
	// They are claims, not proof: the trust list supplies the other half.
	Claims CertificateClaims
	// Qualified reports whether every QES condition held at signing time.
	Qualified bool
	// Qualification is the evidence behind Qualified, so a report can explain
	// what is missing instead of asserting a verdict nobody can check.
	Qualification Qualification
	// Format is CAdES, PAdES or XAdES as detected.
	Format string
	// SignedAt is when the signature claims to exist; the timestamp is
	// authoritative when present.
	SignedAt time.Time
	// Timestamped reports whether an RFC 3161 token protects the signature.
	Timestamped bool
	// TimestampAuthority names the TSA, when known.
	TimestampAuthority string
	// Timestamp is the evidence about the authority behind the token. It is
	// separate from Timestamped because "a token exists and is bound" and "the
	// authority is qualified" are different facts with different sources.
	TimestampEvidence TimestampEvidence
	// Integrity reports whether the signed bytes are untouched.
	Integrity Status
	// CertificateStatus reports whether the certificate was valid at signing.
	CertificateStatus Status
	// Trust is the summary judgement.
	Trust TrustLevel
	// Findings lists every statement about this signature.
	Findings []Finding
	// NotBefore and NotAfter are the certificate validity window.
	NotBefore time.Time
	NotAfter  time.Time
	// ExpiredNow reports whether the certificate has expired as of the moment
	// the report was produced. Separate from ExpiredAtSigning: a signature
	// made while the certificate was valid remains valid.
	ExpiredNow bool
	// ExpiredAtSigning reports the fatal case: signed after expiry.
	ExpiredAtSigning bool
	// SelfSigned reports whether the certificate is its own issuer.
	SelfSigned bool
	// Revoked reports a positive revocation answer. It is only meaningful when
	// Revocation.Checked is true: a boolean cannot tell "not revoked" from
	// "never asked", so both travel together.
	Revoked bool
	// RevokedAt is the revocation moment, when known.
	RevokedAt time.Time
	// Revocation is the full outcome, including the cases a boolean loses.
	Revocation RevocationEvidence
}

// DocumentReport is the full verification result for one file.
type DocumentReport struct {
	// Path is the verified file.
	Path string
	// Format is "pdf", "cades" or "xades".
	Format string
	// Signed reports whether any signature was found.
	Signed bool
	// Signers is one entry per signature, in document order.
	Signers []SignerReport
	// Trust is the worst summary across signers: one broken signature makes
	// the whole document untrustworthy.
	Trust TrustLevel
	// VerifiedAt is when the report was produced.
	VerifiedAt time.Time
	// Warnings lists document-level problems.
	Warnings []Finding
}

// Verdict computes the overall trust from the individual signers.
//
// The worst result wins. A document with four good signatures and one broken
// one is not "mostly fine": it is a document whose content changed after
// somebody signed it.
func (r DocumentReport) Verdict() TrustLevel {
	if !r.Signed || len(r.Signers) == 0 {
		return TrustUnknown
	}

	worst := TrustQualified
	for _, signer := range r.Signers {
		if trustRank(signer.Trust) > trustRank(worst) {
			worst = signer.Trust
		}
	}
	return worst
}

// trustRank orders levels from best (0) to worst.
func trustRank(level TrustLevel) int {
	switch level {
	case TrustQualified:
		return 0
	case TrustAdvanced:
		return 1
	case TrustUnknown:
		return 2
	case TrustUntrusted:
		return 3
	case TrustInvalid:
		return 4
	case TrustBroken:
		return 5
	}
	return 2
}

// Worst returns the most severe status among the findings.
func Worst(findings []Finding) Status {
	worst := StatusGood
	for _, finding := range findings {
		if finding.Status.Severity() > worst.Severity() {
			worst = finding.Status
		}
	}
	return worst
}

// IsFailure reports whether the report should make a caller refuse the file.
func (r DocumentReport) IsFailure() bool {
	switch r.Verdict() {
	case TrustBroken, TrustInvalid, TrustUntrusted:
		return true
	}
	return false
}

// Summary renders a one-line verdict for logs and terminal output.
func (r DocumentReport) Summary() string {
	if !r.Signed {
		return "not signed"
	}
	return fmt.Sprintf("%d signature(s), verdict: %s", len(r.Signers), r.Verdict())
}
