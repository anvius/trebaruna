package integration_test

// End-to-end verification: sign with this tool, verify with this tool, then
// confirm the verdict changes when the document is tampered with. OpenSSL and
// signxml are used in the signing tests; here the subject is our own verifiers,
// which is what a user runs.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	"codeberg.org/simplicer/firma-it/src/signing/domain"
	"codeberg.org/simplicer/firma-it/src/signing/infrastructure"
	verificationinfra "codeberg.org/simplicer/firma-it/src/verification/infrastructure"
)

// fixture is a throwaway identity plus a PEM bundle.
type fixture struct {
	directory string
	pemPath   string
}

// newFixture creates a self-signed identity on disk.
func newFixture(t *testing.T) fixture {
	t.Helper()

	directory := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{
			CommonName:   "Maria Lopez Garcia",
			Organization: []string{"ACME EXAMPLE SL"},
			SerialNumber: "IDCES-00000000X",
			Country:      []string{"ES"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
	path := filepath.Join(directory, "identity.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return fixture{directory: directory, pemPath: path}
}

// signer builds the domain signer for the fixture.
func (f fixture) signer(t *testing.T) domain.Signer {
	t.Helper()

	content, err := os.ReadFile(f.pemPath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	signer, err := domain.NewSigner("Maria Lopez Garcia", domain.FromPEM,
		domain.WithKeyMaterial(content))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	return signer
}

// TestCadesVerifierAcceptsItsOwnOutput signs a file and verifies it back.
func TestCadesVerifierAcceptsItsOwnOutput(t *testing.T) {
	fixture := newFixture(t)

	adapter := infrastructure.NewCadesSigner(nil)
	signed, err := adapter.SignCades(t.Context(), cadesRequest(fixture, t, []byte("contenido")))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	path := filepath.Join(fixture.directory, "doc.txt.p7m")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	reports, err := verificationinfra.NewCadesVerifier().Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(reports))
	}

	report := reports[0]
	if report.Integrity != "good" {
		t.Errorf("integrity = %s, want good (findings %+v)", report.Integrity, report.Findings)
	}
	if report.SignerName != "Maria Lopez Garcia" {
		t.Errorf("signer = %q", report.SignerName)
	}
	if report.Identifier != "IDCES-00000000X" {
		t.Errorf("identifier = %q", report.Identifier)
	}
	// The signing time is only claimed by the signer; there is no RFC 3161 token.
	if report.Timestamped {
		t.Error("an untimestamped CMS must not be reported as timestamped")
	}
	if !report.SelfSigned {
		t.Error("a self-signed certificate must be flagged")
	}
	if report.Trust != "untrusted" {
		t.Errorf("trust = %s, want untrusted for a self-signed certificate", report.Trust)
	}
}

// TestCadesVerifierDetectsTampering changes one byte of the container.
func TestCadesVerifierDetectsTampering(t *testing.T) {
	fixture := newFixture(t)

	adapter := infrastructure.NewCadesSigner(nil)
	signed, err := adapter.SignCades(t.Context(), cadesRequest(fixture, t, []byte("contenido original")))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Flip a byte inside the embedded content, which is what digest covers.
	index := strings.Index(string(signed), "contenido original")
	if index < 0 {
		t.Fatal("cannot locate the embedded content")
	}
	tampered := make([]byte, len(signed))
	copy(tampered, signed)
	tampered[index] = 'X'

	path := filepath.Join(fixture.directory, "tampered.p7m")
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	reports, err := verificationinfra.NewCadesVerifier().Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if reports[0].Integrity != "bad" {
		t.Errorf("integrity = %s, want bad", reports[0].Integrity)
	}
	if reports[0].Trust != "broken" {
		t.Errorf("trust = %s, want broken", reports[0].Trust)
	}
}

// TestCadesTimestampIsNotTrustedWithoutVerification: the tool must not use an
// unauthenticated token as proof of signing time.
func TestCadesTimestampIsNotTrustedWithoutVerification(t *testing.T) {
	fixture := newFixture(t)

	adapter := infrastructure.NewCadesSigner(nil)
	signed, err := adapter.SignCades(t.Context(), cadesRequest(fixture, t, []byte("contenido")))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	path := filepath.Join(fixture.directory, "doc.p7m")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	reports, err := verificationinfra.NewCadesVerifier().Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if reports[0].Timestamped {
		t.Error("a token that was not authenticated must not be reported as trusted")
	}
	if reports[0].Trust == "qualified" {
		t.Error("no CMS must reach the qualified verdict before token validation exists")
	}
}

// TestXadesVerifierAcceptsItsOwnOutput covers the enveloped profile.
func TestXadesVerifierAcceptsItsOwnOutput(t *testing.T) {
	fixture := newFixture(t)
	source := []byte(`<fattura><numero>1</numero></fattura>`)

	adapter := infrastructure.NewXadesSigner(nil)
	signed, err := adapter.SignXades(t.Context(), xadesRequest(fixture, t, source, false))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	path := filepath.Join(fixture.directory, "doc.xml")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	report := reports[0]
	if report.Integrity != "good" {
		t.Errorf("integrity = %s, want good (findings %+v)", report.Integrity, report.Findings)
	}
	if report.SignerName != "Maria Lopez Garcia" {
		t.Errorf("signer = %q", report.SignerName)
	}
	if report.SignedAt.IsZero() {
		t.Error("the XAdES signing time was not read")
	}
}

// TestXadesVerifierDetectsTampering changes the signed payload.
func TestXadesVerifierDetectsTampering(t *testing.T) {
	fixture := newFixture(t)
	source := []byte(`<fattura><numero>1</numero></fattura>`)

	adapter := infrastructure.NewXadesSigner(nil)
	signed, err := adapter.SignXades(t.Context(), xadesRequest(fixture, t, source, false))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tampered := strings.Replace(string(signed), "<numero>1</numero>", "<numero>9</numero>", 1)
	path := filepath.Join(fixture.directory, "tampered.xml")
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if reports[0].Integrity != "bad" {
		t.Errorf("integrity = %s, want bad", reports[0].Integrity)
	}
	if reports[0].Trust != "broken" {
		t.Errorf("trust = %s, want broken", reports[0].Trust)
	}
}

// TestVerifiersRejectMissingFiles keeps the CLI error messages honest.
func TestVerifiersRejectMissingFiles(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.pdf")

	if _, err := verificationinfra.NewCadesVerifier().Extract(missing); err == nil {
		t.Error("a missing file must be reported")
	}
	if _, err := verificationinfra.NewXadesVerifier().Extract(missing); err == nil {
		t.Error("a missing file must be reported")
	}
}

// cadesRequest builds a signing request.
func cadesRequest(fixture fixture, t *testing.T, content []byte) application.CadesRequest {
	return application.CadesRequest{
		Content: content,
		Signer:  fixture.signer(t),
		Level:   domain.BES,
	}
}

// xadesRequest builds an XML signing request.
func xadesRequest(fixture fixture, t *testing.T, content []byte, enveloping bool) application.XadesRequest {
	return application.XadesRequest{
		Content:    content,
		Signer:     fixture.signer(t),
		Level:      domain.BES,
		Enveloping: enveloping,
	}
}
