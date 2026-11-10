package integration_test

// A Brainpool key in a file: Go has no arithmetic to sign with it, and
// trebaruna signs with such keys on a card only. The refusal says so, for
// a PKCS#12 file and for a PEM bundle, instead of Go's "unsupported
// elliptic curve".

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
)

func TestABrainpoolKeyInAFileIsRefusedSayingWhy(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	run := func(arguments ...string) {
		t.Helper()
		command := exec.Command("openssl", arguments...)
		command.Dir = directory
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", arguments, err, output)
		}
	}
	run("ecparam", "-name", "brainpoolP384r1", "-genkey", "-noout", "-out", "key.pem")
	run("req", "-x509", "-new", "-key", "key.pem", "-subj", "/CN=Datei", "-days", "2", "-out", "certificate.pem")
	run("pkcs12", "-export", "-inkey", "key.pem", "-in", "certificate.pem", "-out", "key.p12", "-passout", "pass:segreto")
	read := func(name string) []byte {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		return content
	}

	p12, _ := domain.NewSigner("Datei", domain.FromP12, domain.WithKeyMaterial(read("key.p12")), domain.WithPassphrase("segreto"))
	bundle, _ := domain.NewSigner("Datei", domain.FromPEM, domain.WithKeyMaterial(append(read("certificate.pem"), read("key.pem")...)))
	for name, signer := range map[string]domain.Signer{"PKCS#12": p12, "PEM": bundle} {
		_, err := infrastructure.LoadKeyPair(signer)
		if !errors.Is(err, brainpool.ErrKeyInFile) || !strings.Contains(err.Error(), "brainpoolP384r1") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Another certificate is no reason to refuse.
	run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "p256.key", "-subj", "/CN=P256",
		"-days", "2", "-outform", "DER", "-out", "p256.der")
	if err := brainpool.KeyInFile(read("p256.der")); err != nil {
		t.Errorf("a P-256 certificate: %v", err)
	}
}
