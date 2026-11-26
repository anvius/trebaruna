//go:build cgo

package infrastructure_test

// A store lists only what can sign: a certificate with its private key, valid
// today, not an authority's, with a signature usage. The fixture holds the
// others a browser's store holds: an authority's root without its key, an
// expired certificate, an authority's certificate with its key, a certificate
// that cannot sign, and one whose key is not in the store.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// fixtureIdentity issues a self-signed certificate and its key, written as PEM.
func fixtureIdentity(t *testing.T, directory, name, common string, notBefore, notAfter time.Time,
	usage x509.KeyUsage, authority bool) (certificatePath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: common},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     usage,
	}
	if authority {
		template.IsCA, template.BasicConstraintsValid = true, true
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath = filepath.Join(directory, name+".crt.pem")
	keyPath = filepath.Join(directory, name+".key.pem")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}

// TestTheListingOffersOnlyWhatCanSign lists a store holding usable and unusable
// certificates, and checks that only the usable ones with their keys are offered.
func TestTheListingOffersOnlyWhatCanSign(t *testing.T) {
	for _, tool := range []string{"certutil", "pk12util", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
	if infrastructure.NSSModule() == "" {
		t.Skip("NSS's softokn3 is not installed")
	}

	work := t.TempDir()
	directory := filepath.Join(work, "profile")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	run(t, "certutil", "-N", "-d", "sql:"+directory, "--empty-password")

	now := time.Now()
	year := 365 * 24 * time.Hour
	valid := func(file, common string, usage x509.KeyUsage) (string, string) {
		return fixtureIdentity(t, work, file, common, now.Add(-year), now.Add(year), usage, false)
	}

	// An authority's root without its key: the local channel's root looks so.
	root, _ := fixtureIdentity(t, work, "root", "FIXTURE ROOT", now.Add(-year), now.Add(10*year),
		x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true)
	run(t, "certutil", "-A", "-d", "sql:"+directory, "-n", "FIXTURE ROOT", "-t", "CT,,", "-i", root)

	// Imported with its key, so the store holds a pair that cannot sign.
	pairs := map[string][2]string{}
	cert, key := valid("signing", "ROSSI MARIO", x509.KeyUsageContentCommitment)
	pairs["ROSSI MARIO"] = [2]string{cert, key}
	cert, key = valid("digital", "DIGITAL ONLY", x509.KeyUsageDigitalSignature)
	pairs["DIGITAL ONLY"] = [2]string{cert, key}
	cert, key = valid("encipher", "ENCIPHER ONLY", x509.KeyUsageKeyEncipherment)
	pairs["ENCIPHER ONLY"] = [2]string{cert, key}
	cert, key = fixtureIdentity(t, work, "expired", "EXPIRED", now.Add(-2*year), now.Add(-year), x509.KeyUsageContentCommitment, false)
	pairs["EXPIRED"] = [2]string{cert, key}
	cert, key = fixtureIdentity(t, work, "authority", "FIXTURE AUTHORITY WITH KEY", now.Add(-year), now.Add(10*year),
		x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature, true)
	pairs["FIXTURE AUTHORITY WITH KEY"] = [2]string{cert, key}
	for name, pair := range pairs {
		bundle := filepath.Join(work, name+".p12")
		run(t, "openssl", "pkcs12", "-export", "-inkey", pair[1], "-in", pair[0], "-name", name,
			"-out", bundle, "-passout", "pass:bundle")
		run(t, "pk12util", "-i", bundle, "-d", "sql:"+directory, "-W", "bundle", "-k", emptyPasswordFile(t, work))
	}

	// A certificate whose key is not in the store: it signs for nobody here.
	keyless, _ := fixtureIdentity(t, work, "keyless", "KEYLESS", now.Add(-year), now.Add(year), x509.KeyUsageContentCommitment, false)
	run(t, "certutil", "-A", "-d", "sql:"+directory, "-n", "KEYLESS", "-t", ",,", "-i", keyless)

	inspector := infrastructure.TokenInspector{
		Module:     infrastructure.NSSModule(),
		Parameters: infrastructure.SoftwareStore{Directory: directory}.Parameters(),
	}
	slots, err := inspector.Inspect()
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	var listed []string
	for _, slot := range slots {
		for _, certificate := range slot.Certificates {
			listed = append(listed, certificate.Subject)
		}
	}

	want := []string{"ROSSI MARIO", "DIGITAL ONLY"}
	if len(listed) != len(want) {
		t.Fatalf("listed %v, want the two that can sign: %v", listed, want)
	}
	for _, name := range want {
		if !containsName(listed, name) {
			t.Errorf("%s is not listed among %v", name, listed)
		}
	}
	for _, name := range []string{"FIXTURE ROOT", "EXPIRED", "ENCIPHER ONLY", "FIXTURE AUTHORITY WITH KEY", "KEYLESS"} {
		if containsName(listed, name) {
			t.Errorf("%s must not be offered to sign", name)
		}
	}
}

// emptyPasswordFile is the password file of a store without a primary password.
func emptyPasswordFile(t *testing.T, work string) string {
	t.Helper()
	path := filepath.Join(work, "empty-password")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// containsName reports whether a listed subject names the common name.
func containsName(subjects []string, name string) bool {
	for _, subject := range subjects {
		if strings.Contains(subject, "CN="+name+",") || strings.HasSuffix(subject, "CN="+name) {
			return true
		}
	}
	return false
}

// TestAStoreWithAPrimaryPasswordListsItsUsableCertificates: its private keys
// are hidden until the password is typed, so the listing judges the certificate
// by its own rules and does not ask for the password; the authorities' roots
// stay out.
func TestAStoreWithAPrimaryPasswordListsItsUsableCertificates(t *testing.T) {
	directory, _ := nssStore(t, "clave-maestra")

	inspector := infrastructure.TokenInspector{
		Module:     infrastructure.NSSModule(),
		Parameters: infrastructure.SoftwareStore{Directory: directory}.Parameters(),
	}
	slots, err := inspector.Inspect()
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	var listed []string
	for _, slot := range slots {
		for _, certificate := range slot.Certificates {
			listed = append(listed, certificate.Subject)
		}
	}
	if len(listed) != 1 || !containsName(listed, "ROSSI MARIO") {
		t.Errorf("listed %v without the primary password, want the signing certificate", listed)
	}
}
