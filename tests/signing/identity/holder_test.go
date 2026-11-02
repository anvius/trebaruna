package identity_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/domain/identity"
)

// buildCertificate creates a certificate with the given subject attributes.
func buildCertificate(t *testing.T, subject pkix.Name) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}

// TestUsesGivenNameAndSurname is the regression guard for the first version,
// which printed "MARIA…" because it truncated the common name.
func TestUsesGivenNameAndSurname(t *testing.T) {
	certificate := buildCertificate(t, pkix.Name{
		Country:      []string{"ES"},
		Organization: []string{"ACME EXAMPLE SL"},
		CommonName:   "00000000X MARIA LOPEZ GARCIA",
		SerialNumber: "IDCES-00000000X",
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "MARIA"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "LOPEZ GARCIA"},
		},
	})

	holder := identity.FromCertificate(certificate)

	if holder.Name != "MARIA LOPEZ GARCIA" {
		t.Errorf("name = %q, want the full given name and surname", holder.Name)
	}
	if holder.Identifier != "IDCES-00000000X" {
		t.Errorf("identifier = %q, want the subject serialNumber", holder.Identifier)
	}
}

// TestFallsBackToCommonName keeps self-signed certificates usable.
func TestFallsBackToCommonName(t *testing.T) {
	certificate := buildCertificate(t, pkix.Name{CommonName: "Mario Rossi"})

	holder := identity.FromCertificate(certificate)
	if holder.Name != "Mario Rossi" {
		t.Errorf("name = %q, want the common name", holder.Name)
	}
}

// TestNeverInventsAnIdentifier: a certificate without serialNumber must not
// print a made-up value.
func TestNeverInventsAnIdentifier(t *testing.T) {
	certificate := buildCertificate(t, pkix.Name{CommonName: "Mario Rossi"})

	holder := identity.FromCertificate(certificate)
	if holder.Identifier != "" {
		t.Errorf("identifier = %q, want empty when the certificate carries none", holder.Identifier)
	}
}

// TestOrganizationIdentifierIsReadFromExtraNames covers the eIDAS 2.5.4.97
// attribute, which Go does not expose as a struct field.
func TestOrganizationIdentifierIsReadFromExtraNames(t *testing.T) {
	certificate := buildCertificate(t, pkix.Name{
		CommonName: "Studio Rossi",
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: "VATIT-00000000000"},
		},
	})

	holder := identity.FromCertificate(certificate)
	if holder.Identifier != "VATIT-00000000000" {
		t.Errorf("identifier = %q, want the organizationIdentifier", holder.Identifier)
	}
}

// TestSerialNumberWinsOverOrganizationIdentifier: for a natural person the
// fiscal code identifies the signer better than the company VAT.
func TestSerialNumberWinsOverOrganizationIdentifier(t *testing.T) {
	certificate := buildCertificate(t, pkix.Name{
		CommonName:   "Mario Rossi",
		SerialNumber: "TINIT-ABCDE12A34F567X",
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: "VATIT-00000000000"},
		},
	})

	holder := identity.FromCertificate(certificate)
	if holder.Identifier != "TINIT-ABCDE12A34F567X" {
		t.Errorf("identifier = %q, want the fiscal code", holder.Identifier)
	}
}

// TestEmptyCertificateDoesNotPanic: a malformed certificate must degrade, not crash.
func TestEmptyCertificateDoesNotPanic(t *testing.T) {
	holder := identity.FromCertificate(&x509.Certificate{})
	if holder.Name != "" || holder.Identifier != "" {
		t.Errorf("empty certificate produced %+v", holder)
	}
}
