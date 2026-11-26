package domain_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// usableCertificate issues a certificate the test can parse back, so the
// fields the predicate reads are the ones a token's certificate carries.
func usableCertificate(t *testing.T, notBefore, notAfter time.Time, usage x509.KeyUsage, authority bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "FIXTURE"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     usage,
	}
	if authority {
		template.IsCA = true
		template.BasicConstraintsValid = true
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// TestOnlyACertificateThatCanSignIsUsableForSigning: a root, an expired
// certificate and one that cannot sign are not offered; a signature usage
// valid today is.
func TestOnlyACertificateThatCanSignIsUsableForSigning(t *testing.T) {
	now := time.Now()
	year := 365 * 24 * time.Hour
	valid := func(usage x509.KeyUsage) *x509.Certificate {
		return usableCertificate(t, now.Add(-year), now.Add(year), usage, false)
	}

	cases := []struct {
		name        string
		certificate *x509.Certificate
		want        bool
	}{
		{"non-repudiation, valid", valid(x509.KeyUsageContentCommitment), true},
		{"digital signature, valid", valid(x509.KeyUsageDigitalSignature), true},
		{"both signature usages", valid(x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment), true},
		{"key encipherment only", valid(x509.KeyUsageKeyEncipherment), false},
		{"no key usage declared", valid(0), false},
		{"expired", usableCertificate(t, now.Add(-2*year), now.Add(-year), x509.KeyUsageContentCommitment, false), false},
		{"not yet valid", usableCertificate(t, now.Add(year), now.Add(2*year), x509.KeyUsageContentCommitment, false), false},
		{"certificate authority root", usableCertificate(t, now.Add(-year), now.Add(10*year),
			x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature, true), false},
		{"no certificate", nil, false},
	}
	for _, tc := range cases {
		if got := domain.UsableForSigning(tc.certificate, now); got != tc.want {
			t.Errorf("%s: usable = %t, want %t", tc.name, got, tc.want)
		}
	}
}
