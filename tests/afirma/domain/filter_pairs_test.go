package domain_test

// ssl: and qualified: name a certificate by serial number and may offer its
// signing pair from the same store instead (AutoFirma's SSLFilter and
// QualifiedCertificatesFilter): the identity card's authentication
// certificate, used to log in, stands for the card's signing certificate.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
)

var (
	dnieAuthority = pkix.Name{CommonName: "AC DNIE 004", OrganizationalUnit: []string{"DNIE"},
		Organization: []string{"DIRECCION GENERAL DE LA POLICIA"}, Country: []string{"ES"}}
	otherAuthority = pkix.Name{CommonName: "AC FNMT Usuarios", Organization: []string{"FNMT-RCM"}, Country: []string{"ES"}}
)

// card issues one identity of a holder: serial, holder number, issuer,
// usage and expiry.
func card(t *testing.T, serial int64, holder string, issuer pkix.Name, usage x509.KeyUsage, notAfter time.Time) *x509.Certificate {
	t.Helper()
	return issue(t, certificateSpec{serial: serial, issuer: issuer, usage: usage, notAfter: notAfter,
		subject: pkix.Name{CommonName: "GARCIA LOPEZ, MARIA", SerialNumber: holder, Country: []string{"ES"}}})
}

func offered(t *testing.T, filter string, certificate *x509.Certificate, neighbours ...*x509.Certificate) bool {
	t.Helper()
	parsed := domain.FilterFrom(map[string]string{"filter": filter})
	if !parsed.Pairs() || len(parsed.Unsupported) > 0 {
		t.Fatalf("%s: pairs %t, unsupported %v", filter, parsed.Pairs(), parsed.Unsupported)
	}
	return parsed.Accepts(certificate, neighbours, time.Now())
}

func TestSSLOffersTheCardsSigningCertificateForItsAuthenticationOne(t *testing.T) {
	expiry := time.Now().Add(30 * 24 * time.Hour)
	authentication := card(t, 0x0A1B, "12345678Z", dnieAuthority, x509.KeyUsageDigitalSignature, expiry)
	signing := card(t, 0x0A1C, "12345678Z", dnieAuthority, x509.KeyUsageContentCommitment, expiry)

	if offered(t, "ssl:0A1B", authentication, signing) {
		t.Error("the card's authentication certificate is never offered for signing")
	}
	if !offered(t, "ssl:0A1B", signing, authentication) {
		t.Error("its signing pair is")
	}
	if !offered(t, "ssl: 00 0a 1b #", signing, authentication) {
		t.Error("spaces, # and leading zeros in the serial are ignored")
	}
	if offered(t, "ssl:0A1B", signing) {
		t.Error("without the authentication certificate in the store there is no pair")
	}
	if offered(t, "ssl:0A1D", signing, authentication) {
		t.Error("the pair is of the certificate the serial names")
	}
	if offered(t, "ssl:0A1B", card(t, 0x0A1D, "12345678Z", dnieAuthority, x509.KeyUsageDigitalSignature, expiry), authentication) ||
		offered(t, "ssl:0A1B", card(t, 0x0A1E, "12345678Z", otherAuthority, x509.KeyUsageContentCommitment, expiry), authentication) {
		t.Error("only the card's signing certificate pairs with it")
	}
	if offered(t, "ssl:0A1B", signing, card(t, 0x0A1B, "87654321X", dnieAuthority, x509.KeyUsageDigitalSignature, expiry)) {
		t.Error("another holder's authentication certificate is no pair")
	}
	if offered(t, "ssl:0A1B", signing, card(t, 0x0A1B, "12345678Z", dnieAuthority, x509.KeyUsageDigitalSignature, expiry.Add(72*time.Hour))) {
		t.Error("another card of the same holder (another expiry) is no pair")
	}

	software := card(t, 0x0A1B, "12345678Z", otherAuthority, x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment, expiry)
	if !offered(t, "ssl:0A1B", software) || offered(t, "ssl:0A1D", software) {
		t.Error("any other certificate is offered by its own serial alone")
	}
}

func TestQualifiedOffersTheSigningPairOfTheNamedCertificate(t *testing.T) {
	expiry := time.Now().Add(30 * 24 * time.Hour)
	signing := card(t, 0x51, "12345678Z", otherAuthority, x509.KeyUsageContentCommitment, expiry)
	if !offered(t, "qualified:51", signing) {
		t.Error("a signing certificate named by its serial")
	}
	twin := card(t, 0x55, "12345678Z", otherAuthority, x509.KeyUsageContentCommitment, expiry)
	if !offered(t, "qualified:51", signing, twin) || offered(t, "qualified:51", twin, signing) {
		t.Error("a named signing certificate is offered itself, whatever else the store holds")
	}

	authentication := card(t, 0x50, "12345678Z", otherAuthority, x509.KeyUsageDigitalSignature, expiry)
	if !offered(t, "qualified:50", authentication) {
		t.Error("with no signing pair, the named certificate itself")
	}
	if offered(t, "qualified:50", authentication, signing) || !offered(t, "qualified:50", signing, authentication) {
		t.Error("with a signing pair, the pair instead")
	}
	for name, stranger := range map[string]*x509.Certificate{
		"another issuer": card(t, 0x52, "12345678Z", dnieAuthority, x509.KeyUsageContentCommitment, expiry),
		"another holder": card(t, 0x53, "87654321X", otherAuthority, x509.KeyUsageContentCommitment, expiry),
		"another expiry": card(t, 0x54, "12345678Z", otherAuthority, x509.KeyUsageContentCommitment, expiry.Add(72*time.Hour)),
	} {
		if offered(t, "qualified:50", stranger, authentication) {
			t.Errorf("%s: not a pair", name)
		}
	}

	dnieAuthentication := card(t, 0x60, "12345678Z", dnieAuthority, x509.KeyUsageDigitalSignature, expiry)
	if offered(t, "qualified:60", dnieAuthentication) {
		t.Error("an identity card's authentication certificate alone is never offered")
	}
}

// TestTheValencianAuthoritySignsWithDigitalSignature: under ACCV-CA2 a
// signing certificate carries digital signature and nothing else.
func TestTheValencianAuthoritySignsWithDigitalSignature(t *testing.T) {
	accv := pkix.Name{CommonName: "ACCV-CA2", OrganizationalUnit: []string{"PKIGVA"}, Organization: []string{"Generalitat Valenciana"}, Country: []string{"ES"}}
	expiry := time.Now().Add(30 * 24 * time.Hour)
	named := card(t, 0x70, "12345678Z", accv, x509.KeyUsageKeyEncipherment, expiry)
	signing := card(t, 0x71, "12345678Z", accv, x509.KeyUsageDigitalSignature, expiry)
	if !offered(t, "qualified:70", signing, named) || offered(t, "qualified:70", named, signing) {
		t.Error("ACCV-CA2's signing pattern")
	}
	if offered(t, "qualified:70", card(t, 0x72, "12345678Z", accv, x509.KeyUsageContentCommitment, expiry), named) {
		t.Error("under ACCV-CA2 non-repudiation alone is not the signing pattern")
	}
}

func TestABadSerialIsNotUnderstood(t *testing.T) {
	for _, filter := range []string{"ssl:", "ssl:xyz", "qualified:-5"} {
		if parsed := domain.FilterFrom(map[string]string{"filter": filter}); len(parsed.Unsupported) != 1 {
			t.Errorf("%s: unsupported %v", filter, parsed.Unsupported)
		}
	}
	if domain.FilterFrom(map[string]string{"filter": "dnie:"}).Pairs() {
		t.Error("only ssl: and qualified: look at the store")
	}
}
