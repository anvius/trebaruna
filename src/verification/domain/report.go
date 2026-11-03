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

// SignerReport is everything known about one signature in the document.
type SignerReport struct {
	// FieldName is the signature field, e.g. "F38a".
	FieldName string
	// SignerName is the subject common name.
	SignerName string
	// Identifier is the national identifier from the certificate.
	Identifier string
	// Issuer is the CA that issued the certificate.
	Issuer string
	// Format is CAdES, PAdES or XAdES as detected.
	Format string
	// SignedAt is when the signature claims to exist; the timestamp is
	// authoritative when present.
	SignedAt time.Time
	// Timestamped reports whether an RFC 3161 token protects the signature.
	Timestamped bool
	// TimestampAuthority names the TSA, when known.
	TimestampAuthority string
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
	// Revoked reports a revocation, when a status source was consulted.
	Revoked bool
	// RevokedAt is the revocation moment, when known.
	RevokedAt time.Time
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
	case TrustBroken:
		return 4
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
	case TrustBroken, TrustUntrusted:
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
