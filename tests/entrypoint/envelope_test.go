package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// opensslRecipient makes an RSA key, its certificate and a .p12 with OpenSSL.
func opensslRecipient(t *testing.T, directory, name, passphrase string) (certificate, key, bundle string) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	certificate, key, bundle = filepath.Join(directory, name+".pem"), filepath.Join(directory, name+".key"), filepath.Join(directory, name+".p12")
	for _, arguments := range [][]string{
		{"req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", certificate, "-days", "2",
			"-subj", "/CN=" + name, "-addext", "keyUsage=critical,keyEncipherment,digitalSignature"},
		{"pkcs12", "-export", "-inkey", key, "-in", certificate, "-out", bundle, "-passout", "pass:" + passphrase},
	} {
		if output, err := exec.Command("openssl", arguments...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", arguments, err, output)
		}
	}
	return certificate, key, bundle
}

// TestAnEnvelopeOpensForItsRecipientsInOpenSSL.
func TestAnEnvelopeOpensForItsRecipientsInOpenSSL(t *testing.T) {
	directory := t.TempDir()
	certificate, key, _ := opensslRecipient(t, directory, "LUCA", "x")
	document := writeDocument(t, "offerta.pdf", "%PDF-1.4 offerta riservata\n")

	for _, extra := range [][]string{nil, {"--oaep"}} {
		output := filepath.Join(directory, "busta"+strings.Join(extra, "")+".p7e")
		arguments := append([]string{"encrypt", document, "--to", certificate, "--out", output}, extra...)
		if _, stderr, code := run(arguments...); code != 0 {
			t.Fatalf("encrypt %v: %s", extra, stderr)
		}
		opened, err := exec.Command("openssl", "cms", "-decrypt", "-inform", "DER", "-in", output,
			"-recip", certificate, "-inkey", key).Output()
		if err != nil {
			t.Fatalf("openssl cannot open the %v envelope: %v", extra, err)
		}
		original, _ := os.ReadFile(document)
		if !bytes.Equal(opened, original) {
			t.Errorf("%v: openssl got different content", extra)
		}
	}
}

// TestAnOpenSSLEnvelopeOpensWithTheRecipientsP12.
func TestAnOpenSSLEnvelopeOpensWithTheRecipientsP12(t *testing.T) {
	directory := t.TempDir()
	certificate, _, bundle := opensslRecipient(t, directory, "MARIA", "segreto")
	document := writeDocument(t, "verbale.txt", "Verbale riservato\n")
	envelope := filepath.Join(directory, "verbale.txt.p7e")
	if output, err := exec.Command("openssl", "cms", "-encrypt", "-binary", "-aes256", "-outform", "DER",
		"-in", document, "-out", envelope, "-recip", certificate).CombinedOutput(); err != nil {
		t.Fatalf("openssl cms -encrypt: %v\n%s", err, output)
	}
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")

	if _, stderr, code := run("decrypt", envelope, "--p12", bundle); code != 0 {
		t.Fatalf("decrypt: %s", stderr)
	}
	decrypted, err := os.ReadFile(filepath.Join(directory, "verbale.txt"))
	if err != nil || string(decrypted) != "Verbale riservato\n" {
		t.Fatalf("decrypted %q, %v", decrypted, err)
	}
}

// TestAnEnvelopeForSomeoneElseNamesItsRecipients.
func TestAnEnvelopeForSomeoneElseNamesItsRecipients(t *testing.T) {
	directory := t.TempDir()
	certificate, _, _ := opensslRecipient(t, directory, "MARIA", "x")
	_, _, other := opensslRecipient(t, directory, "LUCA", "y")
	document := writeDocument(t, "nota.txt", "per Maria\n")
	if _, stderr, code := run("encrypt", document, "--to", certificate); code != 0 {
		t.Fatalf("encrypt: %s", stderr)
	}
	t.Setenv("TREBARUNA_PASSPHRASE", "y")
	_, stderr, code := run("decrypt", document+".p7e", "--p12", other, "--out", filepath.Join(directory, "out.txt"))
	if code == 0 || !strings.Contains(stderr, "was not encrypted for this certificate") || !strings.Contains(stderr, "serial") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

// TestASigningOnlyCertificateReceivesNothing.
func TestASigningOnlyCertificateReceivesNothing(t *testing.T) {
	directory := t.TempDir()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	certificate := filepath.Join(directory, "firma.pem")
	if output, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", filepath.Join(directory, "k"),
		"-out", certificate, "-days", "2", "-subj", "/CN=FIRMA", "-addext", "keyUsage=critical,nonRepudiation").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	document := writeDocument(t, "a.txt", "a")
	if _, stderr, code := run("encrypt", document, "--to", certificate); code == 0 || !strings.Contains(stderr, "signing only") {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(document + ".p7e"); err == nil {
		t.Error("no envelope may be written")
	}
}
