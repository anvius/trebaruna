package integration_test

// Up to 0.30.0 the XML verifier, built on goxmldsig, checked only the
// reference to the document element: an enveloping signature, whose reference
// names its ds:Object, read as broken, and a change inside the signed
// properties (signing time, policy, role) went unnoticed. Every reference is
// checked now.

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

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"
	signinginfra "codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func signRSAXades(t *testing.T, request application.XadesRequest) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "MARIA GARCIA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})...)
	request.Signer, err = signingdomain.NewSigner(signingdomain.NameFromCertificate, signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signinginfra.NewXadesSigner(nil).SignXades(t.Context(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// TestAnEnvelopingXadesVerifies.
func TestAnEnvelopingXadesVerifies(t *testing.T) {
	signed := signRSAXades(t, application.XadesRequest{Content: []byte(`<acta>1</acta>`), Level: signingdomain.BES, Enveloping: true})
	if got := integrityOf(t, signed); got != "good" {
		t.Errorf("integrity = %s: an enveloping signature references its own Object", got)
	}
}

// TestAChangeInTheSignedPropertiesIsCaught: the signing time is what a
// forger would move.
func TestAChangeInTheSignedPropertiesIsCaught(t *testing.T) {
	signed := signRSAXades(t, application.XadesRequest{Content: []byte(`<acta>1</acta>`), Level: signingdomain.BES})
	start := strings.Index(signed, "<xades:SigningTime>") + len("<xades:SigningTime>")
	forged := signed[:start] + "1999" + signed[start+4:]
	if got := integrityOf(t, forged); got != "bad" {
		t.Errorf("integrity = %s with a moved signing time, want bad", got)
	}
}

// TestSignaturesOfOtherProducersAreJudgedFully: signxml's XAdES verifies,
// and an XPath expression trebaruna does not evaluate reads as unknown, not
// broken.
func TestSignaturesOfOtherProducersAreJudgedFully(t *testing.T) {
	fixtures := filepath.Join("..", "..", "signing", "xmldsig", "testdata")
	report := extractOne(t, verificationinfra.NewXadesVerifier(), filepath.Join(fixtures, "signxml-xades-enveloped.xml"))
	if report.Integrity != "good" {
		t.Errorf("signxml XAdES: %s", report.Integrity)
	}
	report = extractOne(t, verificationinfra.NewXadesVerifier(), filepath.Join(fixtures, "xmlsec-xpath-other.xml"))
	if report.Integrity != "unknown" || !hasFindingCode(report.Findings, "signature.unverifiable") {
		t.Errorf("an unsupported XPath: %s %v", report.Integrity, report.Findings)
	}
	if _, err := os.Stat(filepath.Join(fixtures, "PROVENANCE.md")); err != nil {
		t.Error("the fixtures must say where they come from")
	}
}

// TestEverySignatureOfAnXMLIsReported: a co-signed document reported its
// first signature only, vouching for the second unseen. AutoFirma's
// enveloped transforms (C14N, then the XPath filter) verify.
func TestEverySignatureOfAnXMLIsReported(t *testing.T) {
	fixtures := filepath.Join("..", "..", "signing", "xmldsig", "testdata")
	reports, err := verificationinfra.NewXadesVerifier().Extract(filepath.Join(fixtures, "xmlsec-cosigned.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 {
		t.Fatalf("%d reports, want one per signature", len(reports))
	}
	for index, report := range reports {
		if report.Integrity != "good" {
			t.Errorf("signature %d: %s %v", index+1, report.Integrity, report.Findings)
		}
	}
	if reports[0].SignerName == reports[1].SignerName {
		t.Errorf("both reports name %q: the second must be read from its own KeyInfo", reports[0].SignerName)
	}
	report := extractOne(t, verificationinfra.NewXadesVerifier(), filepath.Join(fixtures, "xmlsec-autofirma-order.xml"))
	if report.Integrity != "good" {
		t.Errorf("AutoFirma's enveloped order: %s %v", report.Integrity, report.Findings)
	}
}
