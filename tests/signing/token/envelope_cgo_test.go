//go:build cgo

package infrastructure_test

// Opening an encrypted envelope with a key that never leaves the card.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
)

func TestACardOpensAnEnvelopeEncryptedForIt(t *testing.T) {
	token, recipient := encryptionCard(t)
	original := []byte("Documento riservato per la carta\n")
	t.Setenv("TREBARUNA_PIN", token.pin)
	document := filepath.Join(t.TempDir(), "riservato.txt")
	os.WriteFile(document, original, 0o600)

	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"encrypt", document, "--to", recipient}, &stdout, &stderr); code != 0 {
		t.Fatalf("encrypt: %s", stderr.String())
	}
	os.Remove(document)

	// No certificate is named: the card's certificate the envelope names is
	// found without the PIN, among the two the card holds.
	stderr.Reset()
	if code := cli.Run([]string{"decrypt", document + ".p7e", "--module", token.module, "--token", token.label},
		&stdout, &stderr); code != 0 {
		t.Fatalf("decrypt with the card: %s", stderr.String())
	}
	decrypted, err := os.ReadFile(document)
	if err != nil || !bytes.Equal(decrypted, original) {
		t.Fatalf("decrypted %q, %v", decrypted, err)
	}
}

// TestACardWithoutTheOAEPHashSaysSo: SoftHSM, like many cards, decrypts OAEP
// with SHA-1 only; an OAEP-SHA-256 envelope gets a reason, not a code.
func TestACardWithoutTheOAEPHashSaysSo(t *testing.T) {
	token, recipient := encryptionCard(t)
	t.Setenv("TREBARUNA_PIN", token.pin)
	document := filepath.Join(t.TempDir(), "nota.txt")
	os.WriteFile(document, []byte("OAEP con SHA-256\n"), 0o600)
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"encrypt", document, "--to", recipient, "--oaep"}, &stdout, &stderr); code != 0 {
		t.Fatalf("encrypt: %s", stderr.String())
	}
	os.Remove(document)
	stderr.Reset()
	code := cli.Run([]string{"decrypt", document + ".p7e", "--module", token.module, "--token", token.label}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "cannot decrypt RSA-OAEP with SHA-256") {
		t.Errorf("exit %d: %s", code, stderr.String())
	}
}

// TestACardOpensAnOAEPEnvelopeWithTheHashItOffers: OpenSSL's OAEP default is
// SHA-1, which SoftHSM decrypts on the token.
func TestACardOpensAnOAEPEnvelopeWithTheHashItOffers(t *testing.T) {
	token, recipient := encryptionCard(t)
	t.Setenv("TREBARUNA_PIN", token.pin)
	directory := t.TempDir()
	document, envelope := filepath.Join(directory, "nota.txt"), filepath.Join(directory, "nota.txt.p7e")
	os.WriteFile(document, []byte("OAEP con SHA-1\n"), 0o600)
	if output, err := exec.Command("openssl", "cms", "-encrypt", "-binary", "-aes256", "-outform", "DER", "-in", document,
		"-out", envelope, "-recip", recipient, "-keyopt", "rsa_padding_mode:oaep").CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v\n%s", err, output)
	}
	os.Remove(document)
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"decrypt", envelope, "--module", token.module, "--token", token.label}, &stdout, &stderr); code != 0 {
		t.Fatalf("decrypt: %s", stderr.String())
	}
	if decrypted, _ := os.ReadFile(document); string(decrypted) != "OAEP con SHA-1\n" {
		t.Errorf("decrypted %q", decrypted)
	}
}

// encryptionCard puts an authentication and an encryption certificate on a
// token and returns the encryption certificate's file.
func encryptionCard(t *testing.T) (softHSM, string) {
	t.Helper()
	token := startSoftHSM(t)
	token.keyPair(t, "01", "authentication")
	token.keyPair(t, "02", "encryption")
	signing := issueCertificateWithUsage(t, token, "01", "digitalSignature")
	if signing == nil {
		t.Skip("openssl is not available to issue a certificate")
	}
	importCertificate(t, token, "01", "authentication", signing)
	encryption := issueCertificateWithUsage(t, token, "02", "keyEncipherment")
	importCertificate(t, token, "02", "encryption", encryption)

	recipient := filepath.Join(t.TempDir(), "recipient.pem")
	os.WriteFile(recipient, encryption, 0o600)
	return token, recipient
}
