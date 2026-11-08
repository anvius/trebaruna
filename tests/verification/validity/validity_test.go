package validity_test

import (
	"testing"
	"time"

	"codeberg.org/anvius/pignus/src/verification/domain"
)

// reference builds a Validity for a certificate valid through 2027, evaluated
// with a fixed "now" so the tests never depend on the machine clock.
func reference() domain.Validity {
	return domain.Validity{
		NotBefore: time.Date(2025, 7, 15, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, 7, 15, 0, 0, 0, 0, time.UTC),
		AtSigning: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC),
		Now:       time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC),
	}
}

// TestValidSignatureIsGood is the baseline.
func TestValidSignatureIsGood(t *testing.T) {
	validity := reference()
	validity.HasTrustedTime = true

	status, findings := validity.Evaluate()
	if status != domain.StatusGood {
		t.Errorf("status = %s, want good (findings: %+v)", status, findings)
	}
	if validity.ExpiredAtSigning() || validity.ExpiredNow() {
		t.Error("a certificate inside its window is not expired")
	}
}

// TestCertificateExpiredAfterSigningStillValidates is the case users get wrong:
// a signature made in 2026 with a certificate that expired in 2027 is fine.
func TestCertificateExpiredAfterSigningStillValidates(t *testing.T) {
	validity := reference()
	validity.HasTrustedTime = true
	validity.Now = time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)

	status, findings := validity.Evaluate()

	if validity.ExpiredAtSigning() {
		t.Fatal("signing happened while the certificate was valid")
	}
	if !validity.ExpiredNow() {
		t.Error("the certificate is expired today and that must be visible")
	}
	if status == domain.StatusBad {
		t.Errorf("an expired-today certificate must not fail a past signature: %+v", findings)
	}
	if status != domain.StatusWarn {
		t.Errorf("status = %s, want warn (expired today)", status)
	}
	assertCode(t, findings, "certificate.expired_now")
}

// TestSignedAfterExpiryIsFatal is the genuinely broken case.
func TestSignedAfterExpiryIsFatal(t *testing.T) {
	validity := reference()
	validity.HasTrustedTime = true
	validity.AtSigning = time.Date(2027, 9, 1, 0, 0, 0, 0, time.UTC)

	status, findings := validity.Evaluate()

	if !validity.ExpiredAtSigning() {
		t.Error("signing after NotAfter must be detected")
	}
	if status != domain.StatusBad {
		t.Errorf("status = %s, want bad", status)
	}
	assertCode(t, findings, "certificate.expired_at_signing")
}

// TestSignedBeforeValidityIsFatal: the clock was wrong, or the file was forged.
func TestSignedBeforeValidityIsFatal(t *testing.T) {
	validity := reference()
	validity.HasTrustedTime = true
	validity.AtSigning = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	status, findings := validity.Evaluate()

	if status != domain.StatusBad {
		t.Errorf("status = %s, want bad", status)
	}
	assertCode(t, findings, "certificate.not_yet_valid_at_signing")
}

// TestUntimestampedSignatureIsWarnedNotRejected: the time is only claimed.
func TestUntimestampedSignatureIsWarnedNotRejected(t *testing.T) {
	validity := reference()
	validity.HasTrustedTime = false

	status, findings := validity.Evaluate()

	if status != domain.StatusWarn {
		t.Errorf("status = %s, want warn", status)
	}
	assertCode(t, findings, "certificate.validity_unproven")
}

// TestRevokedAfterSigningKeepsTheSignature is the other subtle rule: revocation
// protects future signatures, it does not rewrite the past.
func TestRevokedAfterSigningKeepsTheSignature(t *testing.T) {
	validity := reference()
	validity.HasTrustedTime = true
	validity.RevokedAt = time.Date(2027, 1, 10, 0, 0, 0, 0, time.UTC)

	status, findings := validity.Evaluate()

	if status != domain.StatusWarn {
		t.Errorf("status = %s, want warn", status)
	}
	assertCode(t, findings, "certificate.revoked_after_signing")
}

// TestRevokedBeforeSigningIsFatal: the key was already distrusted.
func TestRevokedBeforeSigningIsFatal(t *testing.T) {
	validity := reference()
	validity.HasTrustedTime = true
	validity.RevokedAt = time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	status, findings := validity.Evaluate()

	if status != domain.StatusBad {
		t.Errorf("status = %s, want bad", status)
	}
	assertCode(t, findings, "certificate.revoked_before_signing")
}

// TestRemainingReportsTheUsefulWindow drives the UI hint "expires in N days".
func TestRemainingReportsTheUsefulWindow(t *testing.T) {
	validity := reference()

	remaining := validity.Remaining()
	if remaining <= 0 {
		t.Errorf("remaining = %v, want a positive duration", remaining)
	}
	// 2026-11-03T08:00 to 2027-07-15T00:00 is 253.67 days.
	if days := int(remaining.Hours() / 24); days != 253 {
		t.Errorf("remaining = %d days, want 253", days)
	}
}

// assertCode checks that a specific finding was produced.
func assertCode(t *testing.T, findings []domain.Finding, code string) {
	t.Helper()

	for _, finding := range findings {
		if finding.Code == code {
			if finding.Message == "" {
				t.Errorf("finding %q has no message", code)
			}
			return
		}
	}
	t.Errorf("finding %q not reported; got %+v", code, findings)
}
