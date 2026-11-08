package integration_test

// These tests shell out to openssl: the point is to prove the CMS we build is
// accepted by an independent implementation, not by our own parser.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
)

// fixture holds a throwaway key pair on disk.
type fixture struct {
	directory string
	certPath  string
	keyPath   string
	cert      *x509.Certificate
	key       crypto.Signer
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	directory := t.TempDir()
	certPath := filepath.Join(directory, "c.pem")
	keyPath := filepath.Join(directory, "k.pem")

	generate := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath, "-out", certPath, "-days", "1",
		"-subj", "/C=IT/O=Studio Rossi/CN=Mario Rossi",
		"-addext", "keyUsage=digitalSignature,nonRepudiation",
		"-addext", "extendedKeyUsage=emailProtection")
	if output, err := generate.CombinedOutput(); err != nil {
		t.Fatalf("openssl req failed: %v\n%s", err, output)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	return fixture{
		directory: directory,
		certPath:  certPath,
		keyPath:   keyPath,
		cert:      certificate,
		key:       privateKey.(crypto.Signer),
	}
}

func TestCadesBESVerifiesWithOpenSSL(t *testing.T) {
	fixture := newFixture(t)
	content := []byte("Contenuto di prova\n")

	signature, err := cms.Sign(cms.Request{
		Content:            content,
		Certificate:        fixture.cert,
		Signer:             fixture.key,
		EmbeddedContent:    true,
		IncludeSigningTime: true,
	})
	if err != nil {
		t.Fatalf("cms.Sign: %v", err)
	}

	signaturePath := filepath.Join(fixture.directory, "doc.p7m")
	if err := os.WriteFile(signaturePath, signature.DER, 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	recoveredPath := filepath.Join(fixture.directory, "recovered.txt")
	verify := exec.Command("openssl", "cms", "-verify",
		"-in", signaturePath, "-inform", "DER",
		"-CAfile", fixture.certPath, "-purpose", "any", "-cades",
		"-out", recoveredPath)
	output, err := verify.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl rejected the signature: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "CAdES Verification successful") {
		t.Fatalf("unexpected openssl output: %s", output)
	}

	recovered, err := os.ReadFile(recoveredPath)
	if err != nil {
		t.Fatalf("read recovered content: %v", err)
	}
	if string(recovered) != string(content) {
		t.Errorf("recovered content = %q, want %q", recovered, content)
	}
}

func TestCadesContainsETSIRequiredAttributes(t *testing.T) {
	fixture := newFixture(t)

	signature, err := cms.Sign(cms.Request{
		Content:            []byte("x"),
		Certificate:        fixture.cert,
		Signer:             fixture.key,
		EmbeddedContent:    true,
		IncludeSigningTime: true,
	})
	if err != nil {
		t.Fatalf("cms.Sign: %v", err)
	}

	signaturePath := filepath.Join(fixture.directory, "doc.p7m")
	if err := os.WriteFile(signaturePath, signature.DER, 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	parse := exec.Command("openssl", "asn1parse", "-inform", "DER", "-in", signaturePath)
	output, err := parse.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse: %v\n%s", err, output)
	}

	dump := string(output)
	for _, required := range []string{"contentType", "messageDigest", "signingTime", "signingCertificateV2"} {
		if !strings.Contains(dump, required) {
			t.Errorf("EN 319 122-1 requires %s, which is missing", required)
		}
	}
}

func TestCadesIsNotDetached(t *testing.T) {
	fixture := newFixture(t)
	content := []byte("contenuto embebido")

	signature, err := cms.Sign(cms.Request{
		Content:         content,
		Certificate:     fixture.cert,
		Signer:          fixture.key,
		EmbeddedContent: true,
	})
	if err != nil {
		t.Fatalf("cms.Sign: %v", err)
	}

	// A .p7m carries its content: openssl must recover it without -content.
	signaturePath := filepath.Join(fixture.directory, "doc.p7m")
	if err := os.WriteFile(signaturePath, signature.DER, 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	verify := exec.Command("openssl", "cms", "-verify",
		"-in", signaturePath, "-inform", "DER",
		"-CAfile", fixture.certPath, "-purpose", "any", "-cades",
		"-out", filepath.Join(fixture.directory, "out.txt"))
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("embedded content not recoverable: %v\n%s", err, output)
	}
}

func TestDetachedSignatureNeedsContent(t *testing.T) {
	fixture := newFixture(t)
	content := []byte("contenuto detached")

	signature, err := cms.Sign(cms.Request{
		Content:         content,
		Certificate:     fixture.cert,
		Signer:          fixture.key,
		EmbeddedContent: false,
	})
	if err != nil {
		t.Fatalf("cms.Sign: %v", err)
	}

	signaturePath := filepath.Join(fixture.directory, "detached.p7m")
	contentPath := filepath.Join(fixture.directory, "content.bin")
	if err := os.WriteFile(signaturePath, signature.DER, 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}
	if err := os.WriteFile(contentPath, content, 0o644); err != nil {
		t.Fatalf("write content: %v", err)
	}

	verify := exec.Command("openssl", "cms", "-verify",
		"-in", signaturePath, "-inform", "DER", "-content", contentPath, "-binary",
		"-CAfile", fixture.certPath, "-purpose", "any", "-cades",
		"-out", filepath.Join(fixture.directory, "out.txt"))
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("detached signature failed: %v\n%s", err, output)
	}
}

func TestTamperedContentBreaksVerification(t *testing.T) {
	fixture := newFixture(t)

	signature, err := cms.Sign(cms.Request{
		Content:            []byte("originale"),
		Certificate:        fixture.cert,
		Signer:             fixture.key,
		EmbeddedContent:    true,
		IncludeSigningTime: false,
	})
	if err != nil {
		t.Fatalf("cms.Sign: %v", err)
	}

	// Flip one byte inside the embedded content region.
	tampered := make([]byte, len(signature.DER))
	copy(tampered, signature.DER)
	for index := len(tampered) - 1; index > 0; index-- {
		if tampered[index] == 'o' {
			tampered[index] = 'x'
			break
		}
	}

	tamperedPath := filepath.Join(fixture.directory, "tampered.p7m")
	if err := os.WriteFile(tamperedPath, tampered, 0o644); err != nil {
		t.Fatalf("write tampered signature: %v", err)
	}

	verify := exec.Command("openssl", "cms", "-verify",
		"-in", tamperedPath, "-inform", "DER",
		"-CAfile", fixture.certPath, "-purpose", "any", "-cades",
		"-out", filepath.Join(fixture.directory, "out.txt"))
	if output, err := verify.CombinedOutput(); err == nil {
		t.Fatalf("tampered signature was accepted:\n%s", output)
	}
}

func TestSelfSignedIsStillSignable(t *testing.T) {
	// A self-signed certificate must sign; the tool reports the trust status
	// separately instead of refusing.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "Autofirmado", Country: []string{"ES"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, _ := x509.ParseCertificate(der)

	if _, err := cms.Sign(cms.Request{
		Content:         []byte("autofirmado"),
		Certificate:     certificate,
		Signer:          key,
		EmbeddedContent: true,
	}); err != nil {
		t.Fatalf("self-signed certificate must be signable: %v", err)
	}
}

func TestExtractTokenRejectsRefusedResponse(t *testing.T) {
	// A TimeStampResp with only the status field means the TSA refused.
	refused := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	if _, err := cms.ExtractToken(refused); err == nil {
		t.Fatal("a token-less response must be rejected")
	}
}
