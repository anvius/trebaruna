package domain

import (
	"crypto/x509"
	"math/big"
	"slices"
	"strings"
)

// The ssl: and qualified: filters name a certificate by its serial number
// and may offer, in its place, the signing certificate paired with it in the
// same store, as AutoFirma's SSLFilter and QualifiedCertificatesFilter do.
// The usual case is the Spanish identity card: the page knows the
// authentication certificate the person logged in with and wants the card's
// signing certificate. Pairs share the holder's serial number (the
// SERIALNUMBER attribute, the identity number) and the expiry date.

// pairing reports a condition that looks at the store's other certificates.
func pairing(condition string) bool {
	lower := strings.ToLower(strings.TrimSpace(condition))
	return strings.HasPrefix(lower, "ssl:") || strings.HasPrefix(lower, "qualified:")
}

// sslCondition reads ssl:<serial>: the certificate with that serial, except
// an identity card's authentication certificate, whose place is taken by the
// same card's signing certificate; without one, nothing is offered.
func sslCondition(text string) (condition, bool) {
	serial, ok := pageSerial(text)
	if !ok {
		return nil, false
	}
	return func(certificate *x509.Certificate, in scope) bool {
		if certificate.SerialNumber.Cmp(serial) == 0 {
			return !dnieAuthentication(certificate)
		}
		if !dnieSigning(certificate) {
			return false
		}
		return slices.ContainsFunc(in.neighbours, func(named *x509.Certificate) bool {
			return named.SerialNumber.Cmp(serial) == 0 && dnieAuthentication(named) &&
				certificate.Subject.SerialNumber != "" && strings.EqualFold(certificate.Subject.SerialNumber, named.Subject.SerialNumber) &&
				sameExpiryDate(certificate, named)
		})
	}, true
}

// qualifiedCondition reads qualified:<serial>: the certificate with that
// serial when it is a signing certificate; otherwise its signing pair (same
// issuer, holder serial number and expiry date) when the store holds one,
// and the certificate itself when it does not, unless it is an identity
// card's authentication certificate.
func qualifiedCondition(text string) (condition, bool) {
	serial, ok := pageSerial(text)
	if !ok {
		return nil, false
	}
	return func(certificate *x509.Certificate, in scope) bool {
		if certificate.SerialNumber.Cmp(serial) == 0 {
			if signingCertificate(certificate) {
				return true
			}
			paired := slices.ContainsFunc(in.neighbours, func(other *x509.Certificate) bool {
				return qualifiedPair(certificate, other)
			})
			return !paired && !dnieAuthentication(certificate)
		}
		return slices.ContainsFunc(in.neighbours, func(named *x509.Certificate) bool {
			return named.SerialNumber.Cmp(serial) == 0 && !signingCertificate(named) && qualifiedPair(named, certificate)
		})
	}, true
}

// qualifiedPair reports candidate as the signing pair of named.
func qualifiedPair(named, candidate *x509.Certificate) bool {
	return candidate.SerialNumber.Cmp(named.SerialNumber) != 0 && signingCertificate(candidate) &&
		slices.Equal(named.RawIssuer, candidate.RawIssuer) &&
		named.Subject.SerialNumber == candidate.Subject.SerialNumber && sameExpiryDate(named, candidate)
}

// pageSerial reads a serial number in hexadecimal; spaces, "#" and colons
// are ignored, and so are leading zeros.
func pageSerial(text string) (*big.Int, bool) {
	digits := strings.NewReplacer(" ", "", "#", "", ":", "").Replace(strings.TrimSpace(text))
	serial, ok := new(big.Int).SetString(digits, 16)
	return serial, ok && digits != "" && serial.Sign() >= 0
}

// sameExpiryDate compares the day two certificates expire (in UTC).
func sameExpiryDate(one, other *x509.Certificate) bool {
	const day = "2006-01-02"
	return one.NotAfter.UTC().Format(day) == other.NotAfter.UTC().Format(day)
}

// signingCertificate is AutoFirma's test of a signing certificate: the
// non-repudiation key usage, except under the Valencian ACCV-CA2, whose
// signing certificates carry digital signature alone.
func signingCertificate(certificate *x509.Certificate) bool {
	if certificate.KeyUsage == 0 {
		return false
	}
	issuer := certificate.Issuer
	if issuer.CommonName == "ACCV-CA2" && slices.Equal(issuer.OrganizationalUnit, []string{"PKIGVA"}) &&
		slices.Equal(issuer.Organization, []string{"Generalitat Valenciana"}) && slices.Equal(issuer.Country, []string{"ES"}) {
		return certificate.KeyUsage&^x509.KeyUsageDecipherOnly == x509.KeyUsageDigitalSignature
	}
	return certificate.KeyUsage&x509.KeyUsageContentCommitment != 0
}

// dnieIssuer matches the identity card's issuing authorities.
var dnieIssuer, _ = ldapCondition("(&(cn=AC DNIE *)(ou=DNIE)(o=DIRECCION GENERAL DE LA POLICIA)(c=ES))",
	func(c *x509.Certificate) []byte { return c.RawIssuer })

func dnieAuthentication(certificate *x509.Certificate) bool {
	return certificate.KeyUsage&x509.KeyUsageDigitalSignature != 0 && dnieIssuer(certificate, scope{})
}

func dnieSigning(certificate *x509.Certificate) bool {
	return certificate.KeyUsage&x509.KeyUsageContentCommitment != 0 && dnieIssuer(certificate, scope{})
}
