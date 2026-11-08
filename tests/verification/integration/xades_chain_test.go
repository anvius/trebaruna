package integration_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/anvius/trebaruna/src/signing/application"
	signingdomain "codeberg.org/anvius/trebaruna/src/signing/domain"
	signinginfra "codeberg.org/anvius/trebaruna/src/signing/infrastructure"
	verificationdomain "codeberg.org/anvius/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/anvius/trebaruna/src/verification/infrastructure"
)

// TestXadesChainsToAnExternalRoot is the test this project was missing.
//
// Every other XAdES test signs with a self-signed certificate, so the verifier
// only ever had to answer "does the signature match the certificate it carries".
// That says nothing about the question that matters to a recipient: does this
// document chain to an authority I recognise?
//
// Here a real three-level chain is built — root, intermediate, leaf — the leaf
// is signed with, and the root is offered as the only anchor. The verifier must
// build the path and report the issuer as recognised.
//
// The chain is generated rather than downloaded. A certificate downloaded from
// somewhere expires, and a test that fails when a fixture lapses is a test
// nobody trusts. What is under test is the path building, not any particular
// authority's paperwork.
func TestXadesChainsToAnExternalRoot(t *testing.T) {
	directory := t.TempDir()

	rootCert, rootKey := generateRoot(t, "Trebaruna Test Root")
	intermediateCert, intermediateKey := generateIntermediate(t, rootCert, rootKey, "Trebaruna Test Intermediate")
	leafCert, leafKey := generateLeaf(t, intermediateCert, intermediateKey, "Maria Lopez Garcia")

	bundle := pemBundle(t, leafCert, leafKey)
	signer, err := signingdomain.NewSigner("Maria Lopez Garcia", signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	source := []byte(`<fattura><numero>1</numero><importo>100.00</importo></fattura>`)
	signerAdapter := signinginfra.NewXadesSigner(nil)
	signed, err := signerAdapter.SignXades(t.Context(), application.XadesRequest{
		Content:    source,
		Signer:     signer,
		Level:      signingdomain.BES,
		Enveloping: false,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The leaf carries no chain of its own, so the intermediate must come from
	// somewhere. It is embedded in the document, the way real producers do it.
	document := embedIntermediate(t, string(signed), intermediateCert)

	documentPath := filepath.Join(directory, "signed.xml")
	if err := os.WriteFile(documentPath, []byte(document), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	verifier := verificationinfra.NewXadesVerifier()
	extractor := verifier.WithAnchors(roots, nil)

	report := extractOne(t, extractor, documentPath)

	if report.Integrity != "good" {
		t.Fatalf("integrity = %s, want good (findings %+v)", report.Integrity, report.Findings)
	}
	if report.Trust != verificationdomain.TrustAdvanced {
		t.Errorf("trust = %s, want advanced: the leaf must chain to the anchor", report.Trust)
	}
	if report.CertificateStatus != "good" {
		t.Errorf("certificate status = %s, want good", report.CertificateStatus)
	}
}

// TestXadesWithoutTheChainIsUntrusted pins the reason the previous test passes.
//
// Same document, same anchor, but the intermediate is not embedded. The path
// cannot be built, so the issuer cannot be recognised. A verifier that reported
// "advanced" here would be trusting a document that carries no evidence of
// anything.
func TestXadesWithoutTheChainIsUntrusted(t *testing.T) {
	directory := t.TempDir()

	rootCert, rootKey := generateRoot(t, "Trebaruna Test Root")
	intermediateCert, intermediateKey := generateIntermediate(t, rootCert, rootKey, "Trebaruna Test Intermediate")
	leafCert, leafKey := generateLeaf(t, intermediateCert, intermediateKey, "Maria Lopez Garcia")

	bundle := pemBundle(t, leafCert, leafKey)
	signer, err := signingdomain.NewSigner("Maria Lopez Garcia", signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	source := []byte(`<fattura><numero>1</numero></fattura>`)
	signerAdapter := signinginfra.NewXadesSigner(nil)
	signed, err := signerAdapter.SignXades(t.Context(), application.XadesRequest{
		Content:    source,
		Signer:     signer,
		Level:      signingdomain.BES,
		Enveloping: false,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	documentPath := filepath.Join(directory, "signed.xml")
	if err := os.WriteFile(documentPath, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	verifier := verificationinfra.NewXadesVerifier()
	extractor := verifier.WithAnchors(roots, nil)

	report := extractOne(t, extractor, documentPath)

	if report.Integrity != "good" {
		t.Fatalf("integrity = %s, want good", report.Integrity)
	}
	if report.Trust == verificationdomain.TrustAdvanced {
		t.Error("a document carrying no chain must not read as advanced")
	}
}

// embedIntermediate adds the intermediate certificate to the KeyInfo of a
// signed document, the way a producer that chains to a public authority does.
//
// The insertion is textual on purpose: the signature covers SignedInfo, and
// KeyInfo is not part of what SignedInfo protects for an enveloped signature,
// so adding a certificate beside the leaf does not invalidate it.
func embedIntermediate(t *testing.T, document string, intermediate *x509.Certificate) string {
	t.Helper()

	encoded := base64.StdEncoding.EncodeToString(intermediate.Raw)
	entry := "<ds:X509Certificate>" + encoded + "</ds:X509Certificate>"

	anchor := "</ds:X509Data>"
	index := strings.Index(document, anchor)
	if index < 0 {
		t.Fatal("the signed document has no X509Data to extend")
	}
	return document[:index] + entry + document[index:]
}

// extractOne runs the extractor and returns the single report.
func extractOne(t *testing.T, extractor interface {
	Extract(path string) ([]verificationdomain.SignerReport, error)
}, path string,
) verificationdomain.SignerReport {
	t.Helper()
	reports, err := extractor.Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(reports))
	}
	return reports[0]
}

// pemBundle builds the PEM bundle the signer reads: certificate then key.
func pemBundle(t *testing.T, certificate *x509.Certificate, key *rsa.PrivateKey) []byte {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return append(certificatePEM, keyPEM...)
}

// generateRoot builds a self-signed root.
func generateRoot(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName, Country: []string{"ES"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	return certificate, key
}

// generateIntermediate builds a CA certificate issued by the parent.
func generateIntermediate(t *testing.T, parent *x509.Certificate, parentKey *rsa.PrivateKey, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: commonName, Country: []string{"ES"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	return certificate, key
}

// generateLeaf builds an end-entity certificate issued by the intermediate.
func generateLeaf(t *testing.T, parent *x509.Certificate, parentKey *rsa.PrivateKey, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"ACME EXAMPLE SL"},
			Country:      []string{"ES"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return certificate, key
}

// generateSelfSignedCA builds a self-signed CA certificate.
//
// This is what a trust list publishes as an anchor for an authority that issues
// qualified certificates: the authority itself, self-signed, so that a
// document signed under it can be chained to the anchor the list named.
func generateSelfSignedCA(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: commonName, Country: []string{"ES"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate, key
}
