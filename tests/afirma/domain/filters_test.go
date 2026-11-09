package domain_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
)

type certificateSpec struct {
	subject, issuer pkix.Name
	usage           x509.KeyUsage
	notAfter        time.Time
	policies        []x509.OID
	sscd            bool
}

func issue(t *testing.T, spec certificateSpec) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: spec.issuer, NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: spec.subject, NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter: spec.notAfter, KeyUsage: spec.usage, Policies: spec.policies}
	if spec.sscd {
		statement, _ := asn1.Marshal([]asn1.RawValue{{FullBytes: mustMarshal(t, struct{ ID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}})}})
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}, Value: statement}}
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(raw)
	return certificate
}

func mustOID(t *testing.T, parts ...uint64) x509.OID {
	t.Helper()
	oid, err := x509.OIDFromInts(parts)
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func dnie(t *testing.T, signing bool, notAfter time.Time) *x509.Certificate {
	usage := x509.KeyUsageDigitalSignature
	role := "AUTENTICACION"
	if signing {
		usage, role = x509.KeyUsageContentCommitment, "FIRMA"
	}
	return issue(t, certificateSpec{
		subject:  pkix.Name{CommonName: "GARCIA LOPEZ, MARIA (" + role + ")", SerialNumber: "12345678Z", Country: []string{"ES"}},
		issuer:   pkix.Name{CommonName: "AC DNIE 004", OrganizationalUnit: []string{"DNIE"}, Organization: []string{"DIRECCION GENERAL DE LA POLICIA"}, Country: []string{"ES"}},
		usage:    usage,
		notAfter: notAfter,
	})
}

func accepts(properties map[string]string, certificate *x509.Certificate) bool {
	return domain.FilterFrom(properties).Accepts(certificate, time.Now())
}

func TestWithoutAFilterOnlyValidCertificatesAreOffered(t *testing.T) {
	if !accepts(nil, dnie(t, true, time.Now().Add(time.Hour))) || accepts(nil, dnie(t, true, time.Now().Add(-time.Hour))) {
		t.Error("no filter: valid offered, expired hidden")
	}
}

// TestASubjectFilterPicksThePersonsCertificates is what Sistema RED sends:
// alternatives of RFC 2254 filters on the subject.
func TestASubjectFilterPicksThePersonsCertificates(t *testing.T) {
	maria := dnie(t, true, time.Now().Add(time.Hour))
	properties := map[string]string{
		"filters.1": "subject.rfc2254:(|(serialNumber=12345678Z)(serialNumber=IDCES-12345678Z))",
		"filters.2": "subject.rfc2254:(&(objectClass=*)(cn=*GARCIA*))",
	}
	if !accepts(properties, maria) {
		t.Error("Maria's certificate matches both alternatives")
	}
	other := issue(t, certificateSpec{subject: pkix.Name{CommonName: "ROSSI MARIO", SerialNumber: "TINIT-RSSMRA80"}, notAfter: time.Now().Add(time.Hour)})
	if accepts(properties, other) {
		t.Error("someone else's certificate must not be offered")
	}
	if !accepts(map[string]string{"filter": "subject.rfc2254:(!(cn=ROSSI*))"}, maria) || accepts(map[string]string{"filter": "subject.rfc2254:(!(cn=GARCIA*))"}, maria) {
		t.Error("negation")
	}
	if !accepts(map[string]string{"filter": "subject.rfc2254:(2.5.4.5=12345678Z)"}, maria) {
		t.Error("numeric attribute types")
	}
}

func TestConditionsOfOneFilterMustAllHold(t *testing.T) {
	signing, authentication := dnie(t, true, time.Now().Add(time.Hour)), dnie(t, false, time.Now().Add(time.Hour))
	properties := map[string]string{"filter": "dnie:;nonexpired:"}
	if !accepts(properties, signing) || accepts(properties, authentication) {
		t.Error("dnie: is the DNIe signing certificate")
	}
	if !accepts(map[string]string{"filter": "keyusage.nonrepudiation:true;issuer.contains:policia"}, signing) ||
		accepts(map[string]string{"filter": "keyusage.nonrepudiation:true;issuer.contains:policia"}, authentication) {
		t.Error("key usage and issuer text")
	}
	if !accepts(map[string]string{"filter": "authcert:"}, authentication) || accepts(map[string]string{"filter": "signingcert:"}, authentication) {
		t.Error("signing and authentication certificates")
	}
	expired := dnie(t, true, time.Now().Add(-time.Hour))
	if accepts(map[string]string{"filter": "dnie:;nonexpired:"}, expired) || !accepts(map[string]string{"filter": "dnie:;nonexpired:false"}, expired) {
		t.Error("nonexpired")
	}
}

func TestExactCertificateFilters(t *testing.T) {
	certificate := issue(t, certificateSpec{subject: pkix.Name{CommonName: "A"}, notAfter: time.Now().Add(time.Hour),
		policies: []x509.OID{mustOID(t, 2, 16, 724, 1, 2, 2, 2, 3)}, sscd: true})
	sum := sha1.Sum(certificate.Raw)
	cases := map[string]bool{
		"thumbprint:SHA1:" + hex.EncodeToString(sum[:]):                     true,
		"thumbprint:SHA1:00":                                                false,
		"encodedcert:" + base64.StdEncoding.EncodeToString(certificate.Raw): true,
		"policyid:1.2.3,2.16.724.1.2.2.2.3":                                 true,
		"policyid:1.2.3":                                                    false,
		"sscd:":                                                             true,
	}
	for filter, want := range cases {
		if accepts(map[string]string{"filter": filter}, certificate) != want {
			t.Errorf("%s: want %t", filter, want)
		}
	}
}

// TestAnUnknownConditionOffersNothing: guessing would offer a certificate the
// page did not ask for.
func TestAnUnknownConditionOffersNothing(t *testing.T) {
	filter := domain.FilterFrom(map[string]string{"filter": "ssl:1234;nonexpired:"})
	if filter.Accepts(dnie(t, true, time.Now().Add(time.Hour)), time.Now()) || len(filter.Unsupported) != 1 {
		t.Errorf("unsupported %v", filter.Unsupported)
	}
}
