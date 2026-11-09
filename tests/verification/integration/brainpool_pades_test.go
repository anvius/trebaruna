package integration_test

// PAdES signatures made with brainpool keys: trebaruna's PDF writer adds
// the signature field, and openssl makes the detached CMS envelope over the
// bytes the /ByteRange covers, with a brainpool key; trebaruna's verifier
// reads and checks it.

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/pdffield"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// brainpoolPDF signs a one-page PDF with a brainpool key through openssl.
func brainpoolPDF(t *testing.T, curve string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	run := func(arguments ...string) { brainpoolOpenSSL(t, directory, arguments...) }
	run("ecparam", "-name", curve, "-genkey", "-noout", "-out", "ca.key")
	run("req", "-utf8", "-x509", "-new", "-key", "ca.key", "-subj", "/C=DE/O=Ärztekammer/CN=HBA-CA 7", "-days", "30",
		"-addext", "basicConstraints=critical,CA:true", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "ca.pem")
	run("ecparam", "-name", curve, "-genkey", "-noout", "-out", "signer.key")
	run("req", "-utf8", "-new", "-key", "signer.key", "-subj", "/C=DE/CN=Dr. Anna Müller", "-out", "signer.csr")
	os.WriteFile(filepath.Join(directory, "ext.cnf"), []byte("keyUsage=critical,nonRepudiation\n"), 0o600)
	run("x509", "-req", "-in", "signer.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-days", "30", "-extfile", "ext.cnf", "-out", "signer.pem")

	content, err := os.ReadFile(writeBlankPDF(t, directory))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pdffield.SignNew(content, nil, pdffield.Signature{
		Name: "Dr. Anna Müller", SignedAt: time.Now(), Reserve: 8192,
		Envelope: func(covered []byte) ([]byte, error) {
			os.WriteFile(filepath.Join(directory, "covered"), covered, 0o600)
			run("cms", "-sign", "-binary", "-md", "sha256", "-in", "covered", "-signer", "signer.pem", "-inkey", "signer.key",
				"-certfile", "ca.pem", "-outform", "DER", "-out", "envelope.der")
			return os.ReadFile(filepath.Join(directory, "envelope.der"))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "rezept_signed.pdf")
	os.WriteFile(path, signed, 0o600)
	return path, filepath.Join(directory, "ca.pem")
}

func TestABrainpoolPDFSignatureIsReadAndChecked(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	for _, curve := range []string{"brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"} {
		path, authorityPath := brainpoolPDF(t, curve)
		reports, err := infrastructure.NewPDFVerifier().Extract(path)
		if err != nil || len(reports) != 1 {
			t.Fatalf("%s: %v %+v", curve, err, reports)
		}
		if reports[0].Integrity != domain.StatusGood || reports[0].SignerName != "Dr. Anna Müller" || reports[0].CertificateStatus == domain.StatusGood {
			t.Errorf("%s: integrity %s, signer %q, certificate %s", curve, reports[0].Integrity, reports[0].SignerName, reports[0].CertificateStatus)
		}

		authorityPEM, _ := os.ReadFile(authorityPath)
		block, _ := pem.Decode(authorityPEM)
		authority, _ := brainpool.ParseCertificate(block.Bytes)
		anchored := infrastructure.NewPDFVerifier()
		anchored.Anchors = []*x509.Certificate{authority}
		if reports, err := anchored.Extract(path); err != nil || reports[0].CertificateStatus != domain.StatusGood {
			t.Errorf("%s: the chain to the anchored authority: %v", curve, err)
		}

		content, _ := os.ReadFile(path)
		at := strings.Index(string(content), "/MediaBox")
		content[at+1] = 'X' // /MediaBox becomes /XediaBox
		tampered := filepath.Join(t.TempDir(), "tampered.pdf")
		os.WriteFile(tampered, content, 0o600)
		if reports, err := infrastructure.NewPDFVerifier().Extract(tampered); err != nil || reports[0].Integrity != domain.StatusBad {
			t.Errorf("%s: a changed page: %v %+v", curve, err, reports)
		}
	}
}
