package parser_test

// The QcStatements extension is what the certificate itself claims. These tests
// build real ASN.1, because the failure mode they guard against is a parser that
// silently finds nothing and reports every qualified certificate as unqualified.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"codeberg.org/anvius/pignus/src/trust/infrastructure"
)

// qcExtensionDER builds the extension value the way a real CA does.
func qcExtensionDER(t *testing.T, statements []qcStatementFixture) []byte {
	t.Helper()

	type statement struct {
		ID   asn1.ObjectIdentifier
		Info asn1.RawValue `asn1:"optional"`
	}

	encoded := make([]statement, 0, len(statements))
	for _, fixture := range statements {
		entry := statement{ID: fixture.id}
		if fixture.info != nil {
			der, err := asn1.Marshal(fixture.info)
			if err != nil {
				t.Fatalf("marshal statement info: %v", err)
			}
			entry.Info = asn1.RawValue{FullBytes: der}
		}
		encoded = append(encoded, entry)
	}

	der, err := asn1.Marshal(encoded)
	if err != nil {
		t.Fatalf("marshal qcStatements: %v", err)
	}
	return der
}

// qcStatementFixture is one statement to encode.
type qcStatementFixture struct {
	id   asn1.ObjectIdentifier
	info any
}

// certificateWithStatements issues a certificate carrying the extension.
func certificateWithStatements(t *testing.T, statements []qcStatementFixture) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Example Signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3},
			Critical: false,
			Value:    qcExtensionDER(t, statements),
		}},
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

// TestQCComplianceAndSSCDAreRead pins the two statements that matter for QES.
func TestQCComplianceAndSSCDAreRead(t *testing.T) {
	certificate := certificateWithStatements(t, []qcStatementFixture{
		{id: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}},
		{id: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}},
	})

	statements := infrastructure.ReadQualifiedStatements(certificate)
	if !statements.Recognised {
		t.Fatal("the extension must be recognised")
	}
	if !statements.Compliant {
		t.Error("QcCompliance (0.4.0.1862.1.1) must be detected")
	}
	if !statements.SSCD {
		t.Error("QcSSCD (0.4.0.1862.1.4) must be detected")
	}
	if statements.SignatureCertificate {
		t.Error("no QcType was published, so no signature type may be claimed")
	}
}

// TestQcTypeSignatureIsRead: QcType is a SEQUENCE of OIDs, not a bare value, and
// reading it as a flag makes every seal certificate look like a signer.
func TestQcTypeSignatureIsRead(t *testing.T) {
	certificate := certificateWithStatements(t, []qcStatementFixture{
		{
			id: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6},
			info: []asn1.ObjectIdentifier{
				{0, 4, 0, 1862, 1, 6, 1},
			},
		},
	})

	statements := infrastructure.ReadQualifiedStatements(certificate)
	if !statements.SignatureCertificate {
		t.Error("QcType 0.4.0.1862.1.6.1 means the certificate signs")
	}
}

// TestQcTypeSealIsNotASignature: the same family of statement can declare a
// certificate for seals. Treating any QcType as "can sign" would flatter it.
func TestQcTypeSealIsNotASignature(t *testing.T) {
	certificate := certificateWithStatements(t, []qcStatementFixture{
		{
			id: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6},
			info: []asn1.ObjectIdentifier{
				{0, 4, 0, 1862, 1, 6, 2}, // electronic seal
			},
		},
	})

	statements := infrastructure.ReadQualifiedStatements(certificate)
	if !statements.Recognised {
		t.Fatal("the extension must still be recognised")
	}
	if statements.SignatureCertificate {
		t.Error("a seal certificate must not be reported as a signature certificate")
	}
}

// TestNoExtensionMeansNoClaims: absence of evidence must never become evidence.
func TestNoExtensionMeansNoClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject:      pkix.Name{CommonName: "Plain Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, _ := x509.ParseCertificate(der)

	statements := infrastructure.ReadQualifiedStatements(certificate)
	if statements.Recognised || statements.Compliant || statements.SSCD {
		t.Errorf("a certificate without qcStatements claims nothing, got %+v", statements)
	}
}

// TestMalformedExtensionIsNotGuessed: half-parsed qualification is worse than
// none, because it turns an unparseable claim into a positive verdict.
func TestMalformedExtensionIsNotGuessed(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject:      pkix.Name{CommonName: "Broken Statements"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3},
			Value: []byte{0x30, 0x03, 0x06, 0x01}, // truncated SEQUENCE
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, _ := x509.ParseCertificate(der)

	statements := infrastructure.ReadQualifiedStatements(certificate)
	if statements.Recognised || statements.Compliant {
		t.Errorf("a malformed extension must claim nothing, got %+v", statements)
	}
}

// TestNilCertificateIsSafe keeps the helper usable on a report without one.
func TestNilCertificateIsSafe(t *testing.T) {
	if statements := infrastructure.ReadQualifiedStatements(nil); statements.Recognised {
		t.Error("a missing certificate cannot claim qualification")
	}
}
