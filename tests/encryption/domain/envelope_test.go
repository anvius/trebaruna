package domain_test

import (
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

	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
)

func certificateWith(t *testing.T, key any, usage x509.KeyUsage, notAfter time.Time) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LUCA BIANCHI"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: usage}
	var public, signer any
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		public, signer = &typed.PublicKey, typed
	case *ecdsa.PrivateKey:
		public, signer = &typed.PublicKey, typed
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(raw)
	return certificate
}

func TestOnlyACertificateMeantForKeysReceivesAnEnvelope(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	later, earlier := time.Now().Add(time.Hour), time.Now().Add(-time.Minute)

	cases := []struct {
		name        string
		certificate *x509.Certificate
		want        error
	}{
		{"key encipherment", certificateWith(t, rsaKey, x509.KeyUsageKeyEncipherment, later), nil},
		{"no usage declared", certificateWith(t, rsaKey, 0, later), nil},
		{"signature only", certificateWith(t, rsaKey, x509.KeyUsageContentCommitment, later), encryption.ErrCannotReceive},
		{"elliptic curve", certificateWith(t, ecKey, x509.KeyUsageKeyAgreement, later), encryption.ErrCannotReceive},
		{"expired", certificateWith(t, rsaKey, x509.KeyUsageKeyEncipherment, earlier), encryption.ErrRecipientExpired},
	}
	for _, entry := range cases {
		err := encryption.CanReceive(entry.certificate, time.Now())
		if (entry.want == nil) != (err == nil) || (entry.want != nil && !errors.Is(err, entry.want)) {
			t.Errorf("%s: %v, want %v", entry.name, err, entry.want)
		}
	}
}

func TestTheEnvelopeAndItsDocumentAreNamedBesideEachOther(t *testing.T) {
	if got := encryption.EncryptedName("/tmp/offerta.pdf"); got != "/tmp/offerta.pdf.p7e" {
		t.Errorf("encrypted name %q", got)
	}
	for envelope, want := range map[string]string{"/tmp/offerta.pdf.p7e": "/tmp/offerta.pdf", "/tmp/OFFERTA.P7E": "/tmp/OFFERTA", "/tmp/busta": "/tmp/busta.decrypted"} {
		if got := encryption.DecryptedName(envelope); got != want {
			t.Errorf("%s: %q, want %q", envelope, got, want)
		}
	}
}
