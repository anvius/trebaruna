//go:build cgo

package infrastructure_test

// The Firefox store, opened in place through NSS's own module and checked
// against a real NSS database built by certutil and pk12util.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// nssStore builds an NSS database holding one signing certificate and key,
// protected by the primary password when one is given.
func nssStore(t *testing.T, password string) (directory, ca string) {
	t.Helper()
	for _, tool := range []string{"certutil", "pk12util", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
	if infrastructure.NSSModule() == "" {
		t.Skip("NSS's softokn3 is not installed")
	}

	work := t.TempDir()
	directory = filepath.Join(work, "profile")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(work, "password")
	if err := os.WriteFile(passwordFile, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	create := []string{"-N", "-d", "sql:" + directory, "--empty-password"}
	if password != "" {
		create = []string{"-N", "-d", "sql:" + directory, "-f", passwordFile}
	}
	run(t, "certutil", create...)

	key, certificate, bundle := filepath.Join(work, "key.pem"), filepath.Join(work, "certificate.pem"), filepath.Join(work, "bundle.p12")
	run(t, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", certificate,
		"-days", "2", "-subj", "/CN=ROSSI MARIO/serialNumber=TINIT-RSSMRA80A01H501U",
		"-addext", "keyUsage=critical,nonRepudiation")
	run(t, "openssl", "pkcs12", "-export", "-inkey", key, "-in", certificate, "-out", bundle, "-passout", "pass:bundle")
	run(t, "pk12util", "-i", bundle, "-d", "sql:"+directory, "-W", "bundle", "-k", passwordFile)
	return directory, certificate
}

func run(t *testing.T, tool string, arguments ...string) {
	t.Helper()
	if output, err := exec.Command(tool, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", tool, arguments, err, output)
	}
}

// fingerprints hashes every file of the store, to prove it is left as found.
func fingerprints(t *testing.T, directory string) map[string][32]byte {
	t.Helper()
	sums := map[string][32]byte{}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sums[entry.Name()] = sha256.Sum256(content)
	}
	return sums
}

func signWithStore(t *testing.T, directory, pin string) (string, error) {
	t.Helper()
	document := filepath.Join(t.TempDir(), "lettera.txt")
	if err := os.WriteFile(document, []byte("Firmata con il certificato di Firefox\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TREBARUNA_PIN", pin)
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"sign", document, "--format", "cades", "--nss-db", directory}, &stdout, &stderr); code != 0 {
		return "", errors.New(stderr.String())
	}
	return document + ".p7m", nil
}

// TestAFirefoxStoreSignsInPlace: no export, no copy, no change to the store.
func TestAFirefoxStoreSignsInPlace(t *testing.T) {
	directory, certificate := nssStore(t, "")
	before := fingerprints(t, directory)

	signed, err := signWithStore(t, directory, "")
	if err != nil {
		t.Fatalf("sign with the store: %v", err)
	}
	verify := exec.Command("openssl", "cms", "-verify", "-inform", "DER", "-in", signed,
		"-CAfile", certificate, "-purpose", "any", "-out", os.DevNull)
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("OpenSSL refuses the signature: %v\n%s", err, output)
	}

	after := fingerprints(t, directory)
	for name, sum := range before {
		if after[name] != sum {
			t.Errorf("%s changed: the store must be opened read-only", name)
		}
	}
}

// TestAPrimaryPasswordIsThePIN: Firefox's primary password opens the store;
// none is not tried, a wrong one is named as such.
func TestAPrimaryPasswordIsThePIN(t *testing.T) {
	directory, _ := nssStore(t, "clave-maestra")

	parameters := infrastructure.SoftwareStore{Directory: directory}.Parameters()
	load := func(pin string) error {
		signer, err := domain.NewSigner(domain.NameFromCertificate, domain.FromToken,
			domain.WithToken(infrastructure.NSSModule(), "", pin), domain.WithModuleParameters(parameters))
		if err != nil {
			t.Fatal(err)
		}
		pair, err := infrastructure.LoadKeyPair(signer)
		if err == nil {
			_ = pair.Close()
		}
		return err
	}

	if err := load(""); !errors.Is(err, domain.ErrPINMissing) {
		t.Errorf("no password: %v, want it refused before NSS sees it", err)
	}
	if err := load("sbagliata"); !errors.Is(err, domain.ErrWrongPIN) {
		t.Errorf("wrong password: %v", err)
	}
	if err := load("clave-maestra"); err != nil {
		t.Errorf("the primary password must open the store: %v", err)
	}
}

// TestTheStoreIsListedLikeACard: the window lists it with the same command.
func TestTheStoreIsListedLikeACard(t *testing.T) {
	directory, _ := nssStore(t, "")

	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"token", "--nss-db", directory, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("token --nss-db: %s", stderr.String())
	}
	var listing struct {
		Slots []struct {
			Token        string `json:"token"`
			PIN          string `json:"pin"`
			Certificates []struct {
				Name           string `json:"name"`
				SignsByDefault bool   `json:"signs_by_default"`
			} `json:"certificates"`
		} `json:"slots"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &listing); err != nil {
		t.Fatalf("%v\n%s", err, stdout.String())
	}
	for _, slot := range listing.Slots {
		if len(slot.Certificates) == 0 {
			continue
		}
		if slot.PIN != string(domain.PINNotRequired) || slot.Certificates[0].Name != "ROSSI MARIO" ||
			!slot.Certificates[0].SignsByDefault {
			t.Errorf("listed as %+v", slot)
		}
		return
	}
	t.Fatalf("the store's certificate was not listed:\n%s", stdout.String())
}
