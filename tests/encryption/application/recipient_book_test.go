package application_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/encryption/application"
	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
)

type memoryBook struct {
	saved     map[string]encryption.SavedRecipient
	forgotten []string
	err       error
}

func (b *memoryBook) Saved() ([]encryption.SavedRecipient, error) {
	var all []encryption.SavedRecipient
	for _, recipient := range b.saved {
		all = append(all, recipient)
	}
	return all, b.err
}

func (b *memoryBook) Keep(certificate *x509.Certificate) (encryption.SavedRecipient, error) {
	recipient := encryption.SavedFrom(certificate, "memory")
	b.saved[recipient.Fingerprint] = recipient
	return recipient, nil
}

func (b *memoryBook) Forget(fingerprint string) error {
	b.forgotten = append(b.forgotten, fingerprint)
	delete(b.saved, fingerprint)
	return nil
}

func bookCertificate(t *testing.T, holder string, key any, public any, notAfter time.Time) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: holder},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageKeyEncipherment}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(raw)
	return certificate
}

func TestTheAddressBookKeepsOnlyCertificatesThatReceive(t *testing.T) {
	book := &memoryBook{saved: map[string]encryption.SavedRecipient{}}
	keep := application.NewKeepRecipient(book, time.Now)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	luca := bookCertificate(t, "LUCA BIANCHI", rsaKey, &rsaKey.PublicKey, time.Now().Add(365*24*time.Hour))
	if recipient, err := keep.Execute(context.Background(), luca); err != nil || recipient.Holder != "LUCA BIANCHI" {
		t.Fatalf("an RSA certificate for key encipherment: %+v %v", recipient, err)
	}
	for name, certificate := range map[string]*x509.Certificate{
		"an ECDSA key": bookCertificate(t, "ECDSA", ecKey, &ecKey.PublicKey, time.Now().Add(time.Hour)),
		"expired":      bookCertificate(t, "OLD", rsaKey, &rsaKey.PublicKey, time.Now().Add(-time.Hour)),
	} {
		if _, err := keep.Execute(context.Background(), certificate); err == nil {
			t.Errorf("%s was kept", name)
		}
	}
	listed, err := application.NewListSavedRecipients(book).Execute(context.Background())
	if err != nil || len(listed) != 1 {
		t.Errorf("listed %v, %v", listed, err)
	}

	forget := application.NewForgetRecipient(book)
	if forgotten, err := forget.Execute(context.Background(), "bianchi"); err != nil || forgotten.Holder != "LUCA BIANCHI" || len(book.saved) != 0 {
		t.Errorf("forgotten %+v, %v", forgotten, err)
	}
	if _, err := forget.Execute(context.Background(), "bianchi"); !errors.Is(err, encryption.ErrNoSavedRecipient) {
		t.Errorf("forgetting again: %v", err)
	}
	broken := &memoryBook{saved: map[string]encryption.SavedRecipient{}, err: errors.New("disk")}
	if _, err := application.NewForgetRecipient(broken).Execute(context.Background(), "x"); err == nil || len(broken.forgotten) != 0 {
		t.Errorf("a book that cannot be read forgets nothing: %v", err)
	}
}
