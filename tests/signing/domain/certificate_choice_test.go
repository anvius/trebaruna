package domain_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// cardCertificate issues a throwaway certificate with the given serial and key
// usage, the way a card carries one per key.
func cardCertificate(t *testing.T, serial int64, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "Titolare della carta"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     usage,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}

func fingerprintOf(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}

// TestTheOnlyCertificateIsChosen covers the ordinary card: one key, one
// certificate, nothing to ask.
func TestTheOnlyCertificateIsChosen(t *testing.T) {
	only := cardCertificate(t, 0x10, x509.KeyUsageDigitalSignature)

	index, err := domain.ChooseCertificateBy("").Pick([]*x509.Certificate{only})
	if err != nil || index != 0 {
		t.Fatalf("the only certificate must be chosen, got %d, %v", index, err)
	}
}

// TestTheNonRepudiationCertificateSigns is the Spanish DNIe and the Italian
// signature cards: one certificate authenticates, the other signs, and only the
// one that signs declares non-repudiation.
func TestTheNonRepudiationCertificateSigns(t *testing.T) {
	authentication := cardCertificate(t, 0x20, x509.KeyUsageDigitalSignature)
	signature := cardCertificate(t, 0x21, x509.KeyUsageContentCommitment)

	index, err := domain.ChooseCertificateBy("").Pick([]*x509.Certificate{authentication, signature})
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if index != 1 {
		t.Errorf("the non-repudiation certificate must be chosen, got index %d", index)
	}
}

// TestSeveralSigningCertificatesNeedAChoice: guessing between two certificates
// that can both sign would put a name on the document the person did not pick.
func TestSeveralSigningCertificatesNeedAChoice(t *testing.T) {
	first := cardCertificate(t, 0x30, x509.KeyUsageContentCommitment)
	second := cardCertificate(t, 0x31, x509.KeyUsageContentCommitment)

	_, err := domain.ChooseCertificateBy("").Pick([]*x509.Certificate{first, second})
	if !errors.Is(err, domain.ErrSeveralCertificates) {
		t.Fatalf("two signing certificates must ask for a choice, got %v", err)
	}
}

// TestACertificateIsChosenBySerialOrFingerprint: the selector is what the token
// listing prints, in whatever form the person copied it.
func TestACertificateIsChosenBySerialOrFingerprint(t *testing.T) {
	first := cardCertificate(t, 0x0a1b2c, x509.KeyUsageContentCommitment)
	second := cardCertificate(t, 0x0d4e5f, x509.KeyUsageContentCommitment)
	candidates := []*x509.Certificate{first, second}

	fingerprint := fingerprintOf(second)
	colons := strings.ToUpper(fingerprint[0:2] + ":" + fingerprint[2:4] + ":" + fingerprint[4:6] + ":" + fingerprint[6:8])

	cases := map[string]int{
		"a1b2c":           0,
		"0A1B2C":          0,
		"0x0d4e5f":        1,
		"0d:4e:5f":        1,
		fingerprint:       1,
		fingerprint[:12]:  1,
		colons:            1,
		" " + fingerprint: 1,
	}
	for selector, want := range cases {
		index, err := domain.ChooseCertificateBy(selector).Pick(candidates)
		if err != nil {
			t.Errorf("selector %q: %v", selector, err)
			continue
		}
		if index != want {
			t.Errorf("selector %q chose %d, want %d", selector, index, want)
		}
	}
}

// TestAnUnknownSelectorIsRefused: signing with another certificate than the
// one asked for is never the right answer.
func TestAnUnknownSelectorIsRefused(t *testing.T) {
	only := cardCertificate(t, 0x40, x509.KeyUsageContentCommitment)

	for _, selector := range []string{"41", "deadbeefdeadbeef", "abc"} {
		_, err := domain.ChooseCertificateBy(selector).Pick([]*x509.Certificate{only})
		if !errors.Is(err, domain.ErrNoCertificateMatches) {
			t.Errorf("selector %q must match nothing, got %v", selector, err)
		}
	}
}

// TestAShortFingerprintPrefixIsNotAMatch: fewer than eight digits is too easy to
// match by accident, so it only counts as a serial.
func TestAShortFingerprintPrefixIsNotAMatch(t *testing.T) {
	only := cardCertificate(t, 0x50, x509.KeyUsageContentCommitment)
	prefix := fingerprintOf(only)[:6]

	if strings.TrimLeft(prefix, "0") == "50" {
		t.Skip("the prefix happens to spell the serial")
	}

	_, err := domain.ChooseCertificateBy(prefix).Pick([]*x509.Certificate{only})
	if !errors.Is(err, domain.ErrNoCertificateMatches) {
		t.Errorf("a six-digit prefix must not select by fingerprint, got %v", err)
	}
}

// TestAnEmptyCardHasNothingToChoose.
func TestAnEmptyCardHasNothingToChoose(t *testing.T) {
	_, err := domain.ChooseCertificateBy("").Pick(nil)
	if !errors.Is(err, domain.ErrNoCertificateMatches) {
		t.Errorf("no certificates must match nothing, got %v", err)
	}
}

// TestTheSelectorIsReported: the error messages and the receipt name it.
func TestTheSelectorIsReported(t *testing.T) {
	if got := domain.ChooseCertificateBy(" 0A:1B ").String(); got != "0a1b" {
		t.Errorf("selector rendered as %q", got)
	}
	if !domain.ChooseCertificateBy("").Automatic() {
		t.Error("an empty selector is the automatic choice")
	}
}
