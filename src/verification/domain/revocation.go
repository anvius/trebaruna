package domain

import "time"

// RevocationStatus is the answer to "is this certificate revoked?".
//
// The distinction that matters and that a boolean cannot carry: "we asked and
// the answer was no" is evidence, and "we never asked" is not. Collapsing them
// into false is how a verifier quietly tells a user a certificate is fine when
// nothing was checked.
type RevocationStatus string

const (
	// RevocationGood means a responder said the certificate is not revoked.
	RevocationGood RevocationStatus = "good"

	// RevocationRevoked means a responder said it is revoked.
	RevocationRevoked RevocationStatus = "revoked"

	// RevocationUnknown means the status could not be obtained: offline, no
	// responder published, or the responder answered "try later".
	RevocationUnknown RevocationStatus = "unknown"

	// RevocationUnsupported means the certificate publishes no OCSP or CRL
	// endpoint at all, so no check is possible in principle.
	RevocationUnsupported RevocationStatus = "unsupported"
)

// Revocation is the outcome of a status check for one certificate.
type Revocation struct {
	// Status is the outcome.
	Status RevocationStatus
	// RevokedAt is when the responder says it was revoked, when known.
	RevokedAt time.Time
	// Source is "ocsp", "crl" or empty, so the report can say where the answer
	// came from instead of asserting an anonymous verdict.
	Source string
	// Reason explains a non-good outcome in English.
	Reason string
	// CheckedAt is when the query was made.
	CheckedAt time.Time
	// RawResponse is the responder's answer as it arrived, kept so a signed
	// document can embed it in its /DSS. Without the original bytes the answer
	// cannot be archived, and a revocation status nobody archived is a status
	// that expires with the responder.
	RawResponse []byte
}

// IsRevoked reports a positive revocation answer.
func (r Revocation) IsRevoked() bool { return r.Status == RevocationRevoked }

// WasChecked reports whether a responder gave a definite answer.
//
// It is what separates "not revoked" from "not asked", and the report uses it to
// decide between a clean finding and a warning.
func (r Revocation) WasChecked() bool {
	return r.Status == RevocationGood || r.Status == RevocationRevoked
}

// FatalAtSigning reports whether the revocation invalidates the signature.
//
// A certificate revoked before the signature was made spoils it. One revoked
// afterwards does not: the signer could not have known.
func (r Revocation) FatalAtSigning(signedAt time.Time) bool {
	if !r.IsRevoked() {
		return false
	}
	// Without a revocation date the safest reading is that it applies: assuming
	// the opposite would let a revoked certificate pass on a missing field.
	if r.RevokedAt.IsZero() {
		return true
	}
	if signedAt.IsZero() {
		return true
	}
	return !r.RevokedAt.After(signedAt)
}
