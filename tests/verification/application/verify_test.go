package application_test

// The use case is tested with doubles: the real adapters are exercised by the
// integration tests against OpenSSL and pdfsig.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	trustdomain "codeberg.org/anvius/trebaruna/src/trust/domain"
	"codeberg.org/anvius/trebaruna/src/verification/application"
	"codeberg.org/anvius/trebaruna/src/verification/domain"
)

// fakeExtractor returns prepared signers.
type fakeExtractor struct {
	signers []domain.SignerReport
	err     error
	called  bool
}

func (f *fakeExtractor) Extract(string) ([]domain.SignerReport, error) {
	f.called = true
	return f.signers, f.err
}

// fakeTrust returns a prepared list.
type fakeTrust struct {
	list trustdomain.TrustList
	err  error
}

func (f fakeTrust) Load(string) (trustdomain.TrustList, error) { return f.list, f.err }

// fixedClock freezes time.
type fixedClock struct{ moment time.Time }

func (f fixedClock) Now() time.Time { return f.moment }

// scenario builds a valid signed report.
func scenario() domain.SignerReport {
	return domain.SignerReport{
		FieldName:         "Signature1",
		SignerName:        "Maria Lopez Garcia",
		Issuer:            "ACME EXAMPLE SL",
		Format:            "PAdES",
		SignedAt:          time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC),
		Timestamped:       true,
		Integrity:         domain.StatusGood,
		CertificateStatus: domain.StatusGood,
		NotBefore:         time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Trust:             domain.TrustAdvanced,
	}
}

func newUseCase(signers []domain.SignerReport, list trustdomain.TrustList, listErr error) *application.VerifyDocument {
	return application.NewVerifyDocument(
		&fakeExtractor{signers: signers},
		nil,
		fakeTrust{list: list, err: listErr},
		fixedClock{moment: time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)},
	)
}

func TestVerifyPicksTheExtractorFromTheSuffix(t *testing.T) {
	extractor := &fakeExtractor{signers: []domain.SignerReport{scenario()}}
	useCase := application.NewVerifyDocument(extractor, nil,
		fakeTrust{}, fixedClock{moment: time.Now()})

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !extractor.called {
		t.Error("the PDF extractor was not used for a .pdf path")
	}
	if report.Format != "pdf" {
		t.Errorf("format = %q, want pdf", report.Format)
	}
}

func TestVerifyDetectsCadesBySuffix(t *testing.T) {
	useCase := application.NewVerifyDocument(
		&fakeExtractor{}, &fakeExtractor{signers: []domain.SignerReport{scenario()}},
		fakeTrust{}, fixedClock{moment: time.Now()})

	report, err := useCase.Execute(application.Request{Path: "/tmp/fattura.xml.p7m"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if report.Format != "cades" {
		t.Errorf("format = %q, want cades", report.Format)
	}
}

func TestVerifyReportsUnsupportedFormats(t *testing.T) {
	useCase := newUseCase(nil, trustdomain.TrustList{}, nil)

	report, err := useCase.Execute(application.Request{Path: "/tmp/nota.txt"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if report.Signed {
		t.Error("a text file cannot be signed")
	}
	if domain.Worst(report.Warnings) != domain.StatusUnknown {
		t.Errorf("warnings = %+v, want an unknown-format warning", report.Warnings)
	}
}

func TestVerifyMarksATamperedSignatureAsBroken(t *testing.T) {
	signer := scenario()
	signer.Integrity = domain.StatusBad
	signer.Trust = domain.TrustBroken
	signer.Findings = []domain.Finding{{Code: "signature.modified", Status: domain.StatusBad}}

	useCase := newUseCase([]domain.SignerReport{signer}, trustdomain.TrustList{}, nil)

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if report.Verdict() != domain.TrustBroken {
		t.Errorf("verdict = %s, want broken", report.Verdict())
	}
	if !report.IsFailure() {
		t.Error("a broken signature must be reported as a failure")
	}
}

func TestVerifyDetectsExpiredAtSigning(t *testing.T) {
	signer := scenario()
	// Signed a year after the certificate expired.
	signer.NotAfter = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	signer.SignedAt = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

	useCase := newUseCase([]domain.SignerReport{signer}, trustdomain.TrustList{}, nil)

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := report.Signers[0]
	if !got.ExpiredAtSigning {
		t.Error("signing after expiry must be flagged")
	}
	if got.Trust != domain.TrustInvalid {
		t.Errorf("trust = %s, want invalid", got.Trust)
	}
}

// TestExpiredAtSigningIsInvalidNotBroken pins the distinction that matters most in
// a legal signature tool.
//
// An expired-at-signing certificate leaves the document intact: the bytes did not
// change. Reporting "broken" would accuse someone of tampering with a document
// that nobody touched, and a caller routing on that exit code would reject a
// document it should simply ask to have signed again.
func TestExpiredAtSigningIsInvalidNotBroken(t *testing.T) {
	signer := scenario()
	signer.NotAfter = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	signer.SignedAt = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	signer.Integrity = domain.StatusGood

	useCase := newUseCase([]domain.SignerReport{signer}, trustdomain.TrustList{}, nil)

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := report.Signers[0]
	if got.Trust != domain.TrustInvalid {
		t.Errorf("trust = %s, want invalid", got.Trust)
	}
	if got.Trust == domain.TrustBroken {
		t.Error("an expired-at-signing certificate is not tampering")
	}
	if !got.ExpiredAtSigning {
		t.Error("the reason must still be reported, just more precisely")
	}
	if report.Verdict() != domain.TrustInvalid {
		t.Errorf("verdict = %s, want invalid", report.Verdict())
	}
}

func TestVerifyKeepsAPastSignatureValidAfterExpiry(t *testing.T) {
	signer := scenario()
	// Expired before the frozen "now" (2026-11-03) but after the signing moment
	// (2026-11-02): the exact window this test exists to pin down.
	signer.NotAfter = time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC)

	useCase := newUseCase([]domain.SignerReport{signer}, trustdomain.TrustList{}, nil)

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := report.Signers[0]
	if got.ExpiredAtSigning {
		t.Error("the certificate was valid when the signature was made")
	}
	if !got.ExpiredNow {
		t.Error("the certificate is expired today and that must be visible")
	}
}

func TestVerifyWarnsWhenTheTrustListIsMissing(t *testing.T) {
	useCase := newUseCase([]domain.SignerReport{scenario()}, trustdomain.TrustList{},
		errors.New("no cache"))

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(report.Warnings) == 0 {
		t.Fatal("a missing trust list must be reported")
	}
	if report.Warnings[0].Code != "trustlist.unavailable" {
		t.Errorf("warning = %q", report.Warnings[0].Code)
	}
}

func TestVerifyWarnsWhenTheTrustListIsStale(t *testing.T) {
	list := trustdomain.TrustList{NextUpdate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	useCase := newUseCase([]domain.SignerReport{scenario()}, list, nil)

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(report.Warnings) == 0 || report.Warnings[0].Code != "trustlist.stale" {
		t.Errorf("warnings = %+v, want trustlist.stale", report.Warnings)
	}
}

// TestTrustListInventoryNeverQualifies: a name match in the TSL is inventory,
// not proof. Downloading the file without validating its signature must not
// upgrade a verdict.
func TestTrustListInventoryNeverQualifies(t *testing.T) {
	signer := scenario()
	signer.SelfSigned = false
	signer.Issuer = "ACME EXAMPLE SL"
	signer.Trust = domain.TrustAdvanced

	list := trustdomain.TrustList{
		Services: []trustdomain.TrustService{{
			ProviderName: "ACME EXAMPLE SL", ServiceType: "CA/QC",
			Status: "granted", Qualified: true,
		}},
	}

	useCase := newUseCase([]domain.SignerReport{signer}, list, nil)

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if report.Signers[0].Trust == domain.TrustQualified {
		t.Error("unvalidated TSL inventory must never yield a qualified verdict")
	}
}

func TestSelfSignedIsNeverQualified(t *testing.T) {
	signer := scenario()
	signer.SelfSigned = true
	signer.Trust = domain.TrustUntrusted
	signer.Issuer = "ACME EXAMPLE SL"

	// A trust list that mentions the same issuer name must not upgrade it.
	list := trustdomain.TrustList{
		Services: []trustdomain.TrustService{{
			ProviderName: "ACME EXAMPLE SL",
			ServiceType:  "CA/QC",
			Status:       "granted",
			Qualified:    true,
		}},
	}

	useCase := newUseCase([]domain.SignerReport{signer}, list, nil)

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if report.Signers[0].Trust == domain.TrustQualified {
		t.Error("a self-signed signature must never be reported as qualified")
	}
}

func TestWorstSignerDecidesTheDocument(t *testing.T) {
	good := scenario()
	broken := scenario()
	broken.Trust = domain.TrustBroken

	useCase := newUseCase([]domain.SignerReport{good, broken}, trustdomain.TrustList{}, nil)

	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if report.Verdict() != domain.TrustBroken {
		t.Errorf("verdict = %s, want broken: one broken signature spoils the document", report.Verdict())
	}
}

// TestTrustAnchorsAreOfferedToTheExtractor guards the wiring: without it, every
// qualified signature looks untrusted because its CA is not in the OS store.
func TestTrustAnchorsAreOfferedToTheExtractor(t *testing.T) {
	extractor := &anchorRecorder{signers: []domain.SignerReport{scenario()}}

	list := trustdomain.TrustList{
		Territory: "IT",
		// Only an authenticated list may act as a trust anchor.
		Authenticated: true,
		Services: []trustdomain.TrustService{{
			ProviderName: "Qualified CA",
			ServiceType:  "CA/QC",
			Status:       "granted",
			Qualified:    true,
			Certificates: []*x509.Certificate{selfSignedCA(t)},
		}},
	}

	useCase := application.NewVerifyDocument(extractor, nil,
		fakeTrust{list: list}, fixedClock{moment: time.Now()})

	if _, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !extractor.receivedAnchors {
		t.Error("the extractor was never given the trust list anchors")
	}
}

// anchorRecorder records whether anchors were supplied.
type anchorRecorder struct {
	signers         []domain.SignerReport
	receivedAnchors bool
}

func (a *anchorRecorder) Extract(string) ([]domain.SignerReport, error) { return a.signers, nil }

func (a *anchorRecorder) WithAnchors(roots, intermediates *x509.CertPool) application.DocumentExtractor {
	a.receivedAnchors = roots != nil
	return a
}

// selfSignedCA builds a CA certificate usable as an anchor.
func selfSignedCA(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Qualified CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, _ := x509.ParseCertificate(der)
	return certificate
}

// TestUnauthenticatedListGrantsNoAnchors: a downloaded file is not a trust
// anchor. Until the list signature is checked against a pinned key, its
// certificates must never be offered to a verifier.
func TestUnauthenticatedListGrantsNoAnchors(t *testing.T) {
	extractor := &anchorRecorder{signers: []domain.SignerReport{scenario()}}

	list := trustdomain.TrustList{
		Territory: "IT",
		// Authenticated deliberately left false, as a freshly downloaded file.
		Services: []trustdomain.TrustService{{
			ProviderName: "Qualified CA",
			ServiceType:  "CA/QC",
			Status:       "granted",
			Qualified:    true,
			Certificates: []*x509.Certificate{selfSignedCA(t)},
		}},
	}

	useCase := application.NewVerifyDocument(extractor, nil,
		fakeTrust{list: list}, fixedClock{moment: time.Now()})

	if _, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if extractor.receivedAnchors {
		t.Error("an unauthenticated trust list must not supply trust anchors")
	}
}
