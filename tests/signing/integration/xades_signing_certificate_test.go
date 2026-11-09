package integration_test

// The certificate a XAdES signature names in its signed properties is the
// one its KeyInfo must carry: a certificate with the same key and another
// name put in KeyInfo leaves the signature value valid, and only this
// binding shows the identity was not the one signed.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func findingCodes(report verificationdomain.SignerReport) map[string]bool {
	codes := map[string]bool{}
	for _, finding := range report.Findings {
		codes[finding.Code] = true
	}
	return codes
}

func TestACertificateSwappedIntoKeyInfoIsCaught(t *testing.T) {
	fixture := newFixture(t)
	signed, err := infrastructure.NewXadesSigner(nil).SignXades(context.Background(), application.XadesRequest{
		Content: []byte(`<acta><n>1</n></acta>`), Signer: buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath)),
		Level: domain.BES,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	verify := func(name string, content []byte) verificationdomain.SignerReport {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		reports, err := verificationinfra.NewXadesVerifier().Extract(path)
		if err != nil || len(reports) != 1 {
			t.Fatalf("%v %v", reports, err)
		}
		return reports[0]
	}

	if report := verify("signed.xml", signed); report.Integrity != verificationdomain.StatusGood || !findingCodes(report)["signing_certificate.bound"] {
		t.Fatalf("an untouched signature: %+v", report)
	}

	// Another certificate over the same key: another name, same signature value.
	keyBlock, _ := pem.Decode(readFile(t, fixture.keyPath))
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer := key.(crypto.Signer)
	template := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "Impostor"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	impostor, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, _ := pem.Decode(readFile(t, fixture.certPath))
	swapped := bytes.Replace(signed, []byte(base64.StdEncoding.EncodeToString(certificateBlock.Bytes)),
		[]byte(base64.StdEncoding.EncodeToString(impostor)), 1)
	if bytes.Equal(swapped, signed) {
		t.Fatal("the certificate was not found in the signature")
	}
	report := verify("swapped.xml", swapped)
	codes := findingCodes(report)
	if report.SignerName != "Impostor" || report.Integrity != verificationdomain.StatusBad || report.Trust != verificationdomain.TrustBroken ||
		!codes["signing_certificate.mismatch"] || codes["signature.intact"] {
		t.Errorf("a swapped certificate: %+v", report)
	}
}

// TestACertificateSwappedIntoACMSEnvelopeIsCaught: two certificates over one
// key, with the same issuer and serial (so both answer to the signer's
// identifier, which is not signed) and names of the same length; the
// envelope signed with one carries the other. Only the signing-certificate-v2
// attribute tells them apart.
func TestACertificateSwappedIntoACMSEnvelopeIsCaught(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	issue := func(name string) *x509.Certificate {
		template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, Issuer: pkix.Name{CommonName: name},
			NotBefore: notBefore, NotAfter: notBefore.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		parent := &x509.Certificate{Subject: pkix.Name{CommonName: "Studio Rossi CA"}}
		template.AuthorityKeyId = []byte{1}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	signer, impostor := issue("Mario Rossi"), issue("Mario Rossa")
	if len(signer.Raw) != len(impostor.Raw) {
		t.Skip("the two certificates differ in length")
	}
	envelope, err := cms.Sign(cms.Request{Content: []byte("acta"), Certificate: signer, Signer: key, EmbeddedContent: true})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	check := func(name string, content []byte) verificationdomain.SignerReport {
		path := filepath.Join(directory, name)
		os.WriteFile(path, content, 0o600)
		reports, err := verificationinfra.NewCadesVerifier().Extract(path)
		if err != nil || len(reports) != 1 {
			t.Fatalf("%v %v", reports, err)
		}
		return reports[0]
	}
	if report := check("signed.p7m", envelope.DER); report.Integrity != verificationdomain.StatusGood || !findingCodes(report)["signing_certificate.bound"] {
		t.Fatalf("an untouched envelope: %+v", report.Findings)
	}
	swapped := bytes.Replace(envelope.DER, signer.Raw, impostor.Raw, 1)
	if report := check("swapped.p7m", swapped); report.SignerName != "Mario Rossa" || report.Integrity != verificationdomain.StatusBad ||
		!findingCodes(report)["signing_certificate.mismatch"] {
		t.Errorf("a swapped certificate: %s %s %+v", report.SignerName, report.Integrity, report.Findings)
	}
}

// TestAPDFSignatureIsBoundToItsCertificate: the envelope of each signature
// field is read, and its signing-certificate-v2 checked against the
// certificate the PDF verifier resolved.
func TestAPDFSignatureIsBoundToItsCertificate(t *testing.T) {
	fixture := newFixture(t)
	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content: mustRead(t, writeBlankPDF(t, fixture.directory)), Signer: xadesTestSigner(t), Level: domain.BES, SignedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.directory, "signed.pdf")
	os.WriteFile(path, signed, 0o600)
	reports, err := verificationinfra.NewPDFVerifier().Extract(path)
	if err != nil || len(reports) != 1 || !findingCodes(reports[0])["signing_certificate.bound"] {
		t.Errorf("%+v %v", reports, err)
	}
}
