package application_test

// The QES decision is tested here because it needs three inputs at once: the
// certificate claims, the trust list and the clock. Each test removes one
// condition and asserts that the verdict stays advanced: overstating a signature
// is the failure this tool exists to prevent.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	trustdomain "codeberg.org/simplicer/firma-it/src/trust/domain"
	"codeberg.org/simplicer/firma-it/src/verification/application"
	"codeberg.org/simplicer/firma-it/src/verification/domain"
)

// signingMoment is the frozen instant every test signs at.
var signingMoment = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// qualifiedCA issues a CA certificate whose subject the trust list can publish.
func qualifiedCA(t *testing.T, name string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Example TSP"}},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return certificate
}

// signingReport builds an advanced signature issued by the given CA, carrying
// the claims a qualified certificate publishes.
func signingReport(ca *x509.Certificate) domain.SignerReport {
	return domain.SignerReport{
		FieldName:         "Signature1",
		SignerName:        "Maria Lopez Garcia",
		Issuer:            "Example TSP",
		IssuerDN:          ca.Subject.String(),
		Format:            "PAdES",
		SignedAt:          signingMoment,
		Integrity:         domain.StatusGood,
		CertificateStatus: domain.StatusGood,
		NotBefore:         time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
		Claims: domain.CertificateClaims{
			Recognised:      true,
			Compliant:       true,
			DeviceQualified: true,
			TypeDeclared:    true,
			SignatureType:   true,
		},
		Trust: domain.TrustAdvanced,
	}
}

// qualifiedList publishes the CA as a granted qualified service.
func qualifiedList(ca *x509.Certificate, grantedSince time.Time) trustdomain.TrustList {
	return trustdomain.TrustList{
		Territory:     "IT",
		Authenticated: true,
		Services: []trustdomain.TrustService{{
			ProviderName: "Example TSP",
			ServiceName:  "Example Qualified CA",
			ServiceType:  "CA/QC",
			Status:       trustdomain.StatusGranted,
			StatusSince:  grantedSince,
			Qualified:    true,
			Certificates: []*x509.Certificate{ca},
		}},
	}
}

// verified runs the use case and returns the single signer.
func verified(t *testing.T, signer domain.SignerReport, list trustdomain.TrustList) domain.SignerReport {
	t.Helper()

	useCase := application.NewVerifyDocument(
		&fakeExtractor{signers: []domain.SignerReport{signer}},
		nil,
		fakeTrust{list: list},
		fixedClock{moment: signingMoment.Add(24 * time.Hour)},
	)
	report, err := useCase.Execute(application.Request{Path: "/tmp/atto.pdf"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return report.Signers[0]
}

// TestAllConditionsYieldQualified is the positive case: every eIDAS condition is
// present, so the verdict must reach qualified. Without this test the whole
// feature could be inert, which is exactly how it was before.
func TestAllConditionsYieldQualified(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)

	got := verified(t, signer, qualifiedList(ca, time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)))
	if got.Trust != domain.TrustQualified {
		t.Fatalf("trust = %s, want qualified; missing: %v", got.Trust, got.Qualification.Missing(signingMoment))
	}
	if !got.Qualified {
		t.Error("the report must also record the qualification flag")
	}
	if !got.Qualification.ServiceListed || got.Qualification.ServiceProvider != "Example TSP" {
		t.Errorf("qualification = %+v, want the matched service", got.Qualification)
	}
	if !hasFinding(got.Findings, "signature.qualified") {
		t.Error("a qualified verdict must carry its finding")
	}
}

// TestNoComplianceStatementStaysAdvanced removes the certificate claim.
func TestNoComplianceStatementStaysAdvanced(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.Claims.Compliant = false

	got := verified(t, signer, qualifiedList(ca, time.Time{}))
	if got.Trust != domain.TrustAdvanced {
		t.Errorf("trust = %s, want advanced: the certificate claims nothing", got.Trust)
	}
	if got.Qualified {
		t.Error("without QcCompliance the signature is not qualified")
	}
	if !hasFinding(got.Findings, "signature.not_qualified") {
		t.Error("the report must explain why it is not qualified")
	}
}

// TestNoQualifiedDeviceStaysAdvanced removes the device condition.
func TestNoQualifiedDeviceStaysAdvanced(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.Claims.DeviceQualified = false

	got := verified(t, signer, qualifiedList(ca, time.Time{}))
	if got.Trust != domain.TrustAdvanced {
		t.Errorf("trust = %s, want advanced: no proof of a qualified device", got.Trust)
	}
}

// TestServiceQualifierSuppliesTheDevice covers the other side of the same
// condition: the certificate is silent, but the list says QCWithQSCD.
func TestServiceQualifierSuppliesTheDevice(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.Claims.DeviceQualified = false

	list := qualifiedList(ca, time.Time{})
	list.Services[0].Qualifiers = []string{"QCWithQSCD"}

	got := verified(t, signer, list)
	if got.Trust != domain.TrustQualified {
		t.Fatalf("trust = %s, want qualified: the list publishes QCWithQSCD", got.Trust)
	}
	if got.Qualification.DeviceSource == "" {
		t.Error("the report must say where the device fact came from")
	}
}

// TestUnauthenticatedListNeverQualifies: a downloaded file is inventory. This is
// the difference between reading a list and trusting it.
func TestUnauthenticatedListNeverQualifies(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)

	list := qualifiedList(ca, time.Time{})
	list.Authenticated = false

	got := verified(t, signer, list)
	if got.Trust != domain.TrustAdvanced {
		t.Errorf("trust = %s, want advanced: the list was never authenticated", got.Trust)
	}
	if got.Qualification.ServiceListed {
		t.Error("an unauthenticated list must not satisfy the issuer condition")
	}
}

// TestWithdrawnServiceNeverQualifies: the CA is listed but no longer supervises
// new signatures. This is the case the parser bug used to hide.
func TestWithdrawnServiceNeverQualifies(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)

	list := qualifiedList(ca, time.Time{})
	list.Services[0].Status = trustdomain.StatusWithdrawn

	got := verified(t, signer, list)
	if got.Trust != domain.TrustAdvanced {
		t.Errorf("trust = %s, want advanced: the service is withdrawn", got.Trust)
	}
}

// TestSignatureOlderThanTheGrantStaysAdvanced: a CA approved after the signature
// cannot have issued it, even if it is listed today.
func TestSignatureOlderThanTheGrantStaysAdvanced(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)

	// Granted a month after the document was signed.
	got := verified(t, signer, qualifiedList(ca, signingMoment.Add(30*24*time.Hour)))
	if got.Trust != domain.TrustAdvanced {
		t.Errorf("trust = %s, want advanced: the service was not granted at signing time", got.Trust)
	}
}

// TestGrantBeforeSigningQualifies is the other half of the same rule, so the
// comparison cannot be inverted without a test failing.
func TestGrantBeforeSigningQualifies(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)

	got := verified(t, signer, qualifiedList(ca, signingMoment.Add(-24*time.Hour)))
	if got.Trust != domain.TrustQualified {
		t.Errorf("trust = %s, want qualified: the service was granted before signing", got.Trust)
	}
}

// TestSealCertificateIsNotAQualifiedSignature: an electronic seal is a qualified
// service, but it seals a company's documents; it is not a person's signature.
// The certificate has to say so: QcType present and not "electronic signature".
func TestSealCertificateIsNotAQualifiedSignature(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.Claims.TypeDeclared = true
	signer.Claims.SignatureType = false

	got := verified(t, signer, qualifiedList(ca, time.Time{}))
	if got.Trust != domain.TrustAdvanced {
		t.Errorf("trust = %s, want advanced: the certificate is for seals", got.Trust)
	}
	if got.Qualified {
		t.Error("a seal certificate must not be reported as a qualified signature")
	}
}

// TestAbsentQcTypeIsNotASeal: QcType is optional, and most European signature
// certificates omit it. Reading silence as "seal" was a measured false negative
// on a real Spanish qualified certificate.
func TestAbsentQcTypeIsNotASeal(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.Claims.TypeDeclared = false
	signer.Claims.SignatureType = false

	got := verified(t, signer, qualifiedList(ca, time.Time{}))
	if got.Trust != domain.TrustQualified {
		t.Errorf("trust = %s, want qualified: an absent QcType says nothing", got.Trust)
	}
}

// TestUnknownIssuerCannotBeQualified: the claims are present, but nothing vouches
// for who issued the certificate.
func TestUnknownIssuerCannotBeQualified(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.IssuerDN = "CN=Somebody Else"
	signer.Trust = domain.TrustAdvanced

	got := verified(t, signer, qualifiedList(ca, time.Time{}))
	if got.Trust != domain.TrustAdvanced {
		t.Errorf("trust = %s, want advanced: no listed service issued this chain", got.Trust)
	}
}

// TestBrokenSignatureNeverBecomesQualified: a tampered document must not be
// promoted just because every other condition happens to hold.
func TestBrokenSignatureNeverBecomesQualified(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.Integrity = domain.StatusBad
	signer.Trust = domain.TrustBroken

	got := verified(t, signer, qualifiedList(ca, time.Time{}))
	if got.Trust != domain.TrustBroken {
		t.Errorf("trust = %s, want broken", got.Trust)
	}
}

// TestExpiredAtSigningNeverBecomesQualified covers the other fatal condition.
func TestExpiredAtSigningNeverBecomesQualified(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.NotAfter = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	got := verified(t, signer, qualifiedList(ca, time.Time{}))
	if got.Trust != domain.TrustBroken {
		t.Errorf("trust = %s, want broken: the certificate had expired at signing", got.Trust)
	}
}

// hasFinding reports whether a code appears in the findings.
func hasFinding(findings []domain.Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

// TestUnknownSigningTimeWithGrantDateStaysAdvanced: when the list publishes a
// grant date but the document carries no provable signing time, the comparison
// cannot be made. Silence is not permission.
func TestUnknownSigningTimeWithGrantDateStaysAdvanced(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.SignedAt = time.Time{}

	got := verified(t, signer, qualifiedList(ca, time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)))
	if got.Trust == domain.TrustQualified {
		t.Error("an unknown signing time cannot prove the service was already granted")
	}
	if got.Qualified {
		t.Error("the qualification flag must follow the evidence")
	}
}

// TestNoGrantDateStillQualifies keeps the opposite case working: a list that does
// not publish a date leaves nothing to compare, and the other evidence stands.
func TestNoGrantDateStillQualifies(t *testing.T) {
	ca := qualifiedCA(t, "Example Qualified CA")
	signer := signingReport(ca)
	signer.SignedAt = time.Time{}

	got := verified(t, signer, qualifiedList(ca, time.Time{}))
	if got.Trust != domain.TrustQualified {
		t.Errorf("trust = %s, want qualified: no grant date to contradict", got.Trust)
	}
}
