package pss_test

// RSA-PSS in CMS: the CMS and PDF libraries trebaruna builds on do not
// implement it, and a valid PSS signature was reported as altered. The
// fixtures (testdata/PROVENANCE.md) were made with OpenSSL and accepted by
// it and by poppler's pdfsig; their signer is issued by an authority whose
// key is published as id-RSASSA-PSS, like German qualified authorities.

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/verification/application"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", name)
}

// anchored is the authority as a trust list would publish it.
func anchored(t *testing.T) []*x509.Certificate {
	t.Helper()
	content, err := os.ReadFile(fixture(t, "pss-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(content)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{certificate}
}

// changed writes a copy of a fixture with one change.
func changed(t *testing.T, name string, old, new string) string {
	t.Helper()
	content, err := os.ReadFile(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Replace(content, []byte(old), []byte(new), 1)
	if bytes.Equal(altered, content) {
		t.Fatalf("%s: the change did not apply", name)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func only(t *testing.T, extractor application.DocumentExtractor, path string) domain.SignerReport {
	t.Helper()
	reports, err := extractor.Extract(path)
	if err != nil || len(reports) != 1 {
		t.Fatalf("%s: %v %v", path, reports, err)
	}
	return reports[0]
}

func has(report domain.SignerReport, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func cades(t *testing.T) *verificationinfra.CadesVerifier {
	t.Helper()
	return verificationinfra.NewCadesVerifier().WithAnchorCertificates(nil, nil, anchored(t)).(*verificationinfra.CadesVerifier)
}

func TestAnRSAPSSEnvelopeVerifiesAndChainsThroughAPSSAuthority(t *testing.T) {
	report := only(t, cades(t), fixture(t, "pss-embedded.p7m"))
	if report.Integrity != domain.StatusGood || !has(report, "certificate.trusted") || !has(report, "signing_certificate.bound") {
		t.Errorf("anchored: %+v", report)
	}
	report = only(t, verificationinfra.NewCadesVerifier(), fixture(t, "pss-embedded.p7m"))
	if report.Integrity != domain.StatusGood || !has(report, "certificate.untrusted_issuer") {
		t.Errorf("without the authority: %+v", report)
	}
}

func TestADetachedRSAPSSSignatureNoticesAChangedDocument(t *testing.T) {
	report := only(t, cades(t).WithContent(fixture(t, "documento.txt")), fixture(t, "pss-detached.p7s"))
	if report.Integrity != domain.StatusGood || !has(report, "certificate.trusted") {
		t.Errorf("the document signed: %+v", report)
	}
	other := changed(t, "documento.txt", "RSA-PSS", "RSA-PKCS")
	report = only(t, cades(t).WithContent(other), fixture(t, "pss-detached.p7s"))
	if report.Integrity != domain.StatusBad || !has(report, "signature.modified") {
		t.Errorf("another document: %+v", report)
	}
}

// TestAnAlgorithmTrebarunaLacksIsUnknownNotAltered: the SignerInfo's PSS
// identifier, the last one in the envelope, made 1.2.840.113549.1.1.99.
func TestAnAlgorithmTrebarunaLacksIsUnknownNotAltered(t *testing.T) {
	content, err := os.ReadFile(fixture(t, "pss-embedded.p7m"))
	if err != nil {
		t.Fatal(err)
	}
	oid := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a}
	at := bytes.LastIndex(content, oid)
	content[at+len(oid)-1] = 0x63
	path := filepath.Join(t.TempDir(), "unknown.p7m")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	report := only(t, cades(t), path)
	if report.Integrity != domain.StatusUnknown || !has(report, "signature.unverifiable") {
		t.Errorf("%+v", report)
	}
}

func TestAnRSAPSSPDFSignatureVerifies(t *testing.T) {
	pdf := verificationinfra.NewPDFVerifier().WithAnchorCertificates(nil, nil, anchored(t))
	report := only(t, pdf, fixture(t, "pss-pades.pdf"))
	if report.Integrity != domain.StatusGood || report.Format != "PAdES" || !has(report, "certificate.trusted") ||
		!has(report, "signing_certificate.bound") || report.SignerName != "Erika Mustermann" {
		t.Errorf("%+v", report)
	}
	report = only(t, pdf, changed(t, "pss-pades.pdf", "Documento de prueba PSS", "Documento de prueba XSS"))
	if report.Integrity != domain.StatusBad || !has(report, "signature.modified") {
		t.Errorf("a changed page: %+v", report)
	}
}

// TestAChangedSignedAttributeBreaksTheSignature: the signing time moved by
// a second leaves the messageDigest right; only the PSS signature over the
// attributes can tell.
func TestAChangedSignedAttributeBreaksTheSignature(t *testing.T) {
	content, err := os.ReadFile(fixture(t, "pss-embedded.p7m"))
	if err != nil {
		t.Fatal(err)
	}
	signingTime := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05, 0x31, 0x0f, 0x17, 0x0d}
	at := bytes.Index(content, signingTime)
	if at < 0 {
		t.Fatal("no signing time")
	}
	second := at + len(signingTime) + 11 // YYMMDDhhmmS|S|Z
	content[second] = '0' + (content[second]-'0'+1)%10
	path := filepath.Join(t.TempDir(), "later.p7m")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	report := only(t, cades(t), path)
	if report.Integrity != domain.StatusBad || !has(report, "signature.modified") {
		t.Errorf("%+v", report)
	}
}
