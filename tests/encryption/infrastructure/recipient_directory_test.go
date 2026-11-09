package infrastructure_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
	"codeberg.org/simplicer/trebaruna/src/encryption/infrastructure"
)

func certificateFor(t *testing.T, holder string) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: holder},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	raw, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certificate, _ := x509.ParseCertificate(raw)
	return certificate
}

func TestTheAddressBookLivesInOnePrivateDirectory(t *testing.T) {
	book := infrastructure.RecipientDirectory{Directory: filepath.Join(t.TempDir(), "recipients")}
	if saved, err := book.Saved(); err != nil || len(saved) != 0 {
		t.Fatalf("an empty book: %v %v", saved, err)
	}
	maria, luca := certificateFor(t, "maria rossi"), certificateFor(t, "LUCA BIANCHI")
	for _, certificate := range []*x509.Certificate{maria, luca, maria} {
		if _, err := book.Keep(certificate); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(book.Directory, "notes.pem"), []byte("not a certificate"), 0o600)
	saved, err := book.Saved()
	if err != nil || len(saved) != 2 || saved[0].Holder != "LUCA BIANCHI" || saved[1].Holder != "maria rossi" {
		t.Fatalf("two certificates, by holder, the stray file skipped: %+v %v", saved, err)
	}
	if filepath.Base(saved[1].Location) != encryption.Fingerprint(maria)+".pem" {
		t.Errorf("named by fingerprint: %s", saved[1].Location)
	}
	if err := book.Forget(encryption.Fingerprint(maria)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{encryption.Fingerprint(maria), "../recipients/x", "", "a.b"} {
		if err := book.Forget(name); !errors.Is(err, encryption.ErrNoSavedRecipient) {
			t.Errorf("forgetting %q: %v", name, err)
		}
	}
}
