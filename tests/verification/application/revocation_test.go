package application_test

// The use case decides *when* to ask and what to do with the answer. These tests
// pin the two rules that make the feature safe: it never contacts a responder
// unless configured, and an unanswered query is never reported as good.

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	trustdomain "codeberg.org/simplicer/firma-it/src/trust/domain"
	"codeberg.org/simplicer/firma-it/src/verification/application"
	"codeberg.org/simplicer/firma-it/src/verification/domain"
)

// fakeRevocation answers with a prepared verdict and records the call.
type fakeRevocation struct {
	answer domain.Revocation
	called bool
	issuer *x509.Certificate
}

func (f *fakeRevocation) Check(_ context.Context, _ *x509.Certificate, issuer *x509.Certificate) domain.Revocation {
	f.called = true
	f.issuer = issuer
	return f.answer
}

// revokedScenario builds a report with the certificates a check needs.
func revokedScenario() domain.SignerReport {
	signer := scenario()
	signer.Revocation = domain.RevocationEvidence{
		Certificate: &x509.Certificate{RawSubject: []byte("leaf")},
		Issuer:      &x509.Certificate{RawSubject: []byte("issuer")},
	}
	return signer
}

// withRevocation wires a checker into the use case.
func withRevocation(signer domain.SignerReport, checker application.RevocationChecker) domain.SignerReport {
	useCase := application.NewVerifyDocument(
		&fakeExtractor{signers: []domain.SignerReport{signer}},
		nil,
		fakeTrust{list: trustdomain.TrustList{}},
		fixedClock{moment: time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)},
	).WithRevocation(checker)

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		panic(err)
	}
	return report.Signers[0]
}

// TestNoCheckerMeansNoNetwork is the default that matters: verification must not
// reach a third party unless the caller asked.
func TestNoCheckerMeansNoNetwork(t *testing.T) {
	signer := revokedScenario()

	useCase := newUseCase([]domain.SignerReport{signer}, trustdomain.TrustList{}, nil)
	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := report.Signers[0]
	if got.Revocation.Checked {
		t.Error("without a checker nothing may be reported as checked")
	}
	if got.Revoked {
		t.Error("without a checker nothing may be reported as revoked")
	}
}

// TestCheckedAndNotRevokedIsAGoodFinding: an answered query is evidence and must
// be reported as such, not silently omitted.
func TestCheckedAndNotRevokedIsAGoodFinding(t *testing.T) {
	checker := &fakeRevocation{answer: domain.Revocation{
		Status:    domain.RevocationGood,
		Source:    "ocsp",
		CheckedAt: time.Now(),
	}}

	got := withRevocation(revokedScenario(), checker)
	if !checker.called {
		t.Fatal("a configured checker must be used")
	}
	if !got.Revocation.Checked {
		t.Error("an answered query counts as checked")
	}
	if !hasFinding(got.Findings, "certificate.not_revoked") {
		t.Error("the confirmation must appear in the report")
	}
}

// TestUnansweredQueryIsNotReportedAsGood is the failure this whole design exists
// to prevent.
func TestUnansweredQueryIsNotReportedAsGood(t *testing.T) {
	checker := &fakeRevocation{answer: domain.Revocation{
		Status: domain.RevocationUnknown,
		Reason: "no responder answered",
	}}

	got := withRevocation(revokedScenario(), checker)
	if got.Revocation.Checked {
		t.Error("an unanswered query must not count as checked")
	}
	if got.Revoked {
		t.Error("not knowing is not a revocation")
	}
	if !hasFinding(got.Findings, "certificate.revocation_unchecked") {
		t.Error("the report must say the status could not be obtained")
	}
	if hasFinding(got.Findings, "certificate.not_revoked") {
		t.Error("an unanswered query must never be presented as a confirmation")
	}
}

// TestRevokedBeforeSigningIsFatal covers the case that invalidates a document.
func TestRevokedBeforeSigningIsFatal(t *testing.T) {
	signer := revokedScenario()
	revokedAt := signer.SignedAt.Add(-24 * time.Hour)

	checker := &fakeRevocation{answer: domain.Revocation{
		Status:    domain.RevocationRevoked,
		RevokedAt: revokedAt,
		Source:    "ocsp",
	}}

	got := withRevocation(signer, checker)
	if !got.Revoked {
		t.Error("the revocation must be recorded")
	}
	if !hasFinding(got.Findings, "certificate.revoked_before_signing") {
		t.Error("revoked before signing spoils the signature")
	}
	if got.Trust != domain.TrustBroken {
		t.Errorf("trust = %s, want broken", got.Trust)
	}
}

// TestRevokedAfterSigningKeepsTheSignature: the signer could not have known.
func TestRevokedAfterSigningKeepsTheSignature(t *testing.T) {
	signer := revokedScenario()
	revokedAt := signer.SignedAt.Add(24 * time.Hour)

	checker := &fakeRevocation{answer: domain.Revocation{
		Status:    domain.RevocationRevoked,
		RevokedAt: revokedAt,
		Source:    "ocsp",
	}}

	got := withRevocation(signer, checker)
	if hasFinding(got.Findings, "certificate.revoked_before_signing") {
		t.Error("a later revocation does not invalidate an earlier signature")
	}
	if !hasFinding(got.Findings, "certificate.revoked_after_signing") {
		t.Error("the revocation must still be reported")
	}
	if got.Trust == domain.TrustBroken {
		t.Error("a later revocation must not break the signature")
	}
}

// TestRevocationWithoutCertificateSaysSo: no material, no check, and the report
// must not pretend otherwise.
func TestRevocationWithoutCertificateSaysSo(t *testing.T) {
	signer := scenario()
	checker := &fakeRevocation{answer: domain.Revocation{Status: domain.RevocationGood}}

	got := withRevocation(signer, checker)
	if checker.called {
		t.Error("a check without a certificate cannot be attempted")
	}
	if got.Revocation.Checked {
		t.Error("nothing was checked")
	}
	if got.Revocation.Status.Reason == "" {
		t.Error("the report must explain why")
	}
}

// TestRevocationUsesTheIssuerFromTheDocument: the query needs both certificates.
func TestRevocationUsesTheIssuerFromTheDocument(t *testing.T) {
	signer := revokedScenario()
	checker := &fakeRevocation{answer: domain.Revocation{Status: domain.RevocationGood}}

	withRevocation(signer, checker)
	if checker.issuer == nil {
		t.Error("the issuer must be passed to the checker, or no request can be built")
	}
}

// erroringChecker simulates a transport failure.
type erroringChecker struct{}

func (erroringChecker) Check(context.Context, *x509.Certificate, *x509.Certificate) domain.Revocation {
	return domain.Revocation{Status: domain.RevocationUnknown, Reason: errors.New("connection refused").Error()}
}

// TestTransportFailureIsAWarningNotAFailure: a network problem is a problem with
// our knowledge, not with the document.
func TestTransportFailureIsAWarningNotAFailure(t *testing.T) {
	got := withRevocation(revokedScenario(), erroringChecker{})
	if got.Trust == domain.TrustBroken {
		t.Error("an unreachable responder must not break the signature")
	}
	if !hasFinding(got.Findings, "certificate.revocation_unchecked") {
		t.Error("the failure must be reported")
	}
}
