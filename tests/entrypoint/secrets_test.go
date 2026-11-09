package cli_test

// Secrets can travel in the environment so they never appear in a command line
// that every local user can list. These tests pin the fallback for the
// certificate command, which shares the lookup with sign and the handler.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// writeProtectedP12 creates a self-signed P12 locked with the given passphrase.
func writeProtectedP12(t *testing.T, passphrase string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "MARIO ROSSI"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := pkcs12.Modern.Encode(key, certificate, nil, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mario.p12")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestThePassphraseCanComeFromTheEnvironment(t *testing.T) {
	path := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")

	stdout, stderr, code := run("certificate", path, "--json", "--territory", "EU")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "MARIO ROSSI") {
		t.Errorf("stdout = %q, want the holder", stdout)
	}
}

func TestAnExplicitFlagWinsOverTheEnvironment(t *testing.T) {
	path := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "wrong")

	if _, stderr, code := run("certificate", path, "--pass", "segreto", "--territory", "EU"); code != 0 {
		t.Fatalf("exit %d, stderr %q: the flag must win", code, stderr)
	}
}

func TestWithoutEitherTheBundleStaysLocked(t *testing.T) {
	path := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "")

	if _, _, code := run("certificate", path, "--territory", "EU"); code == 0 {
		t.Fatal("a locked P12 opened without its passphrase")
	}
}

// TestAWrongPassphraseIsNamedAsSuch: the command used to answer "is not a
// certificate, a PEM bundle or a PKCS#12 file", which sent people looking for
// another file when they had mistyped a password.
func TestAWrongPassphraseIsNamedAsSuch(t *testing.T) {
	path := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "")

	_, stderr, code := run("certificate", path, "--pass", "sbagliato", "--territory", "EU")
	if code == 0 || !strings.Contains(stderr, "passphrase does not open") {
		t.Errorf("exit %d, stderr %q: want the passphrase named", code, stderr)
	}

	_, stderr, _ = run("certificate", path, "--territory", "EU")
	if !strings.Contains(stderr, "TREBARUNA_PASSPHRASE") {
		t.Errorf("stderr %q: without a passphrase, say how to give one", stderr)
	}
}

func TestTheCertificateReportsWhereItsHolderIs(t *testing.T) {
	path := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")

	stdout, _, code := run("certificate", path, "--json", "--territory", "EU")
	if code != 0 || !strings.Contains(stdout, `"locality": ""`) || !strings.Contains(stdout, `"issuer_name": "MARIO ROSSI"`) {
		t.Errorf("exit %d, stdout %q: want locality and issuer_name fields", code, stdout)
	}
}
