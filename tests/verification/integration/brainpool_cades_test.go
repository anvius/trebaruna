package integration_test

// CAdES signatures made with Brainpool keys, as German health
// professionals' cards make them: openssl builds the authority, the signer
// and the envelope on each curve; trebaruna reads it, checks its integrity
// and, given the authority as an anchor, its chain.

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func brainpoolOpenSSL(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("openssl", arguments...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("openssl %v: %v\n%s", arguments, err, output)
	}
}

// brainpoolEnvelope signs a document on the curve and returns the
// envelope's path and the authority.
func brainpoolEnvelope(t *testing.T, curve, digest string) (string, *x509.Certificate) {
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
	os.WriteFile(filepath.Join(directory, "rezept.txt"), []byte("Rezept: Ibuprofen 400\n"), 0o600)
	run("cms", "-sign", "-binary", "-nodetach", "-md", digest, "-in", "rezept.txt", "-signer", "signer.pem", "-inkey", "signer.key",
		"-certfile", "ca.pem", "-outform", "DER", "-out", "rezept.p7m")
	authorityPEM, _ := os.ReadFile(filepath.Join(directory, "ca.pem"))
	block, _ := pem.Decode(authorityPEM)
	authority, err := brainpool.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "rezept.p7m"), authority
}

func TestABrainpoolSignatureIsReadAndChecked(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	for curve, digest := range map[string]string{"brainpoolP256r1": "sha256", "brainpoolP384r1": "sha384", "brainpoolP512r1": "sha512"} {
		envelope, authority := brainpoolEnvelope(t, curve, digest)

		reports, err := infrastructure.NewCadesVerifier().Extract(envelope)
		if err != nil || len(reports) != 1 {
			t.Fatalf("%s: %v", curve, err)
		}
		report := reports[0]
		if report.Integrity != domain.StatusGood || report.SignerName != "Dr. Anna Müller" || report.CertificateStatus == domain.StatusGood {
			t.Errorf("%s: integrity %s, signer %q, certificate %s", curve, report.Integrity, report.SignerName, report.CertificateStatus)
		}

		anchored := infrastructure.NewCadesVerifier().WithAnchorCertificates(x509.NewCertPool(), nil, []*x509.Certificate{authority})
		reports, err = anchored.Extract(envelope)
		if err != nil || reports[0].CertificateStatus != domain.StatusGood {
			t.Errorf("%s: the chain to the anchored authority: %v %s", curve, err, reports[0].CertificateStatus)
		}

		forged, _ := os.ReadFile(envelope)
		// The envelope ends with the signature value: its last byte changed.
		forged[len(forged)-1] ^= 1
		forgedPath := filepath.Join(t.TempDir(), "forged.p7m")
		os.WriteFile(forgedPath, forged, 0o600)
		if reports, err := infrastructure.NewCadesVerifier().Extract(forgedPath); err != nil || reports[0].Integrity == domain.StatusGood {
			t.Errorf("%s: an altered signature: %v %+v", curve, err, reports)
		}

		content, _ := os.ReadFile(envelope)
		at := len(content) - 1
		for index := range content {
			if string(content[index:min(index+9, len(content))]) == "Ibuprofen" {
				at = index
				break
			}
		}
		content[at] = 'X'
		tampered := filepath.Join(t.TempDir(), "tampered.p7m")
		os.WriteFile(tampered, content, 0o600)
		if reports, err := infrastructure.NewCadesVerifier().Extract(tampered); err != nil || reports[0].Integrity != domain.StatusBad {
			t.Errorf("%s: a changed prescription: %v %+v", curve, err, reports)
		}
	}
}

// TestAnImpostorAuthorityAnchorsNothing: an anchor with the authority's
// name and another key leaves the chain unverified.
func TestAnImpostorAuthorityAnchorsNothing(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	envelope, _ := brainpoolEnvelope(t, "brainpoolP256r1", "sha256")
	_, impostor := brainpoolEnvelope(t, "brainpoolP256r1", "sha256")
	anchored := infrastructure.NewCadesVerifier().WithAnchorCertificates(x509.NewCertPool(), nil, []*x509.Certificate{impostor})
	reports, err := anchored.Extract(envelope)
	if err != nil || reports[0].CertificateStatus == domain.StatusGood {
		t.Errorf("an impostor anchored the chain: %v %s", err, reports[0].CertificateStatus)
	}
}
