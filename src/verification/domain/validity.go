package domain

import "time"

// Validity answers the question users actually ask: "¿está caducada?".
//
// The answer is not "yes" or "no". A certificate that expired yesterday does
// not invalidate a signature made two years ago while it was valid: that is the
// entire point of long-term validation. What invalidates a signature is having
// been made outside the certificate's window, or made after revocation.
//
// Two distinct facts are therefore reported:
//
//	ExpiredAtSigning  fatal. The certificate was already expired when signed.
//	ExpiredNow        informational. The certificate no longer validates new
//	                  signatures, but existing ones survive if they carry
//	                  proof of the time (a timestamp) or revocation data.
type Validity struct {
	// NotBefore and NotAfter bound the certificate.
	NotBefore time.Time
	NotAfter  time.Time
	// AtSigning is the moment that must fall inside the window. It should be
	// the timestamp when one exists, otherwise the claimed signing time.
	AtSigning time.Time
	// HasTrustedTime reports whether AtSigning is backed by a timestamp. When
	// false, AtSigning is only what the signer claims, and the check is weak.
	HasTrustedTime bool
	// Now is the evaluation moment, injected so tests can freeze it.
	Now time.Time
	// RevokedAt is when the certificate was revoked, if it was.
	RevokedAt time.Time
}

// Evaluate reports the validity findings and the certificate status.
func (v Validity) Evaluate() (Status, []Finding) {
	var findings []Finding
	status := StatusGood

	// 1. Was the certificate within its window at signing time?
	if !v.AtSigning.IsZero() {
		switch {
		case v.AtSigning.Before(v.NotBefore):
			findings = append(findings, Finding{
				Code:    "certificate.not_yet_valid_at_signing",
				Status:  StatusBad,
				Message: "the certificate was not valid yet when the signature was made",
				Detail:  v.AtSigning.UTC().Format(time.RFC3339),
			})
			status = StatusBad
		case v.AtSigning.After(v.NotAfter):
			findings = append(findings, Finding{
				Code:    "certificate.expired_at_signing",
				Status:  StatusBad,
				Message: "the certificate had already expired when the signature was made",
				Detail:  v.AtSigning.UTC().Format(time.RFC3339),
			})
			status = StatusBad
		case !v.HasTrustedTime:
			// Inside the window, but the clock is the signer's own. Worth saying:
			// the user may want a timestamp to make this survive scrutiny.
			findings = append(findings, Finding{
				Code:    "certificate.validity_unproven",
				Status:  StatusWarn,
				Message: "the signing time is declared by the signer and is not timestamped",
				Detail:  v.AtSigning.UTC().Format(time.RFC3339),
			})
			status = StatusWarn
		}
	}

	// 2. Was it revoked before the signature?
	if !v.RevokedAt.IsZero() {
		if v.AtSigning.IsZero() || !v.RevokedAt.After(v.AtSigning) {
			findings = append(findings, Finding{
				Code:    "certificate.revoked_before_signing",
				Status:  StatusBad,
				Message: "the certificate was revoked before the signature was made",
				Detail:  v.RevokedAt.UTC().Format(time.RFC3339),
			})
			status = StatusBad
		} else {
			// Revoked afterwards: reported, but it does not break signatures made
			// while it was still valid.
			findings = append(findings, Finding{
				Code:    "certificate.revoked_after_signing",
				Status:  StatusWarn,
				Message: "the certificate was revoked after signing; the signature itself is unaffected",
				Detail:  v.RevokedAt.UTC().Format(time.RFC3339),
			})
			if status == StatusGood {
				status = StatusWarn
			}
		}
	}

	// 3. Expired today: informational, never fatal on its own.
	if !v.Now.IsZero() && v.Now.After(v.NotAfter) {
		findings = append(findings, Finding{
			Code:    "certificate.expired_now",
			Status:  StatusWarn,
			Message: "the certificate has expired; it can no longer create new signatures",
			Detail:  v.NotAfter.UTC().Format(time.RFC3339),
		})
		if status == StatusGood {
			status = StatusWarn
		}
	}

	return status, findings
}

// ExpiredAtSigning reports the fatal condition.
func (v Validity) ExpiredAtSigning() bool {
	if v.AtSigning.IsZero() {
		return false
	}
	return v.AtSigning.After(v.NotAfter) || v.AtSigning.Before(v.NotBefore)
}

// ExpiredNow reports whether the certificate is past its window as of Now.
func (v Validity) ExpiredNow() bool {
	return !v.Now.IsZero() && v.Now.After(v.NotAfter)
}

// Remaining returns how long the certificate stays usable, which the UI shows
// as "caduca en 43 días" instead of a raw date.
func (v Validity) Remaining() time.Duration {
	if v.Now.IsZero() {
		return 0
	}
	return v.NotAfter.Sub(v.Now)
}
