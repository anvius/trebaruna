package application_test

// A person looked up in a certificate directory: each certificate found is
// said fit to receive an envelope or not, and why.

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

type fakeDirectory struct {
	certificates []*x509.Certificate
	err          error
	asked        []string
}

func (f *fakeDirectory) Find(_ context.Context, who string) ([]*x509.Certificate, error) {
	f.asked = append(f.asked, who)
	return f.certificates, f.err
}

func directoryCertificate(t *testing.T, holder string, usage x509.KeyUsage, notAfter time.Time, ec bool) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: holder},
		NotBefore: notAfter.Add(-48 * time.Hour), NotAfter: notAfter, KeyUsage: usage}
	var raw []byte
	if ec {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		raw, _ = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	} else {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		raw, _ = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	}
	certificate, _ := x509.ParseCertificate(raw)
	return certificate
}

func TestEachCertificateFoundIsSaidFitOrNot(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	directory := &fakeDirectory{certificates: []*x509.Certificate{
		directoryCertificate(t, "MARIA", x509.KeyUsageKeyEncipherment, now.Add(time.Hour), false),
		directoryCertificate(t, "MARIA firma", x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment, now.Add(time.Hour), false),
		directoryCertificate(t, "MARIA caducado", x509.KeyUsageKeyEncipherment, now.Add(-time.Hour), false),
		directoryCertificate(t, "MARIA EC", x509.KeyUsageKeyAgreement, now.Add(time.Hour), true),
	}}
	found, err := application.NewFindRecipient(directory, func() time.Time { return now }).Execute(context.Background(), "maria@example.org")
	if err != nil || len(found) != 4 || len(directory.asked) != 1 || directory.asked[0] != "maria@example.org" {
		t.Fatalf("%d %v %v", len(found), err, directory.asked)
	}
	if found[0].Problem != nil || !errors.Is(found[1].Problem, encryption.ErrCannotReceive) ||
		!errors.Is(found[2].Problem, encryption.ErrRecipientExpired) || !errors.Is(found[3].Problem, encryption.ErrCannotReceive) {
		t.Errorf("problems: %v, %v, %v, %v", found[0].Problem, found[1].Problem, found[2].Problem, found[3].Problem)
	}
	directory.err = errors.New("unreachable")
	if _, err := application.NewFindRecipient(directory, time.Now).Execute(context.Background(), "x"); err == nil {
		t.Error("an unreachable directory found certificates")
	}
}
