// Package identity describes the identity printed on a signing certificate.
package identity

import (
	"crypto/x509"
	"strings"
)

// Holder contains certificate-derived values, never user-entered stamp text.
type Holder struct {
	Name       string
	Identifier string
}

// FromCertificate prefers givenName and surname over a decorated commonName.
// The serialNumber subject attribute is an identity identifier, not the
// certificate serial number. Missing attributes are not invented.
func FromCertificate(certificate *x509.Certificate) Holder {
	attribute := func(oid string) string {
		for _, name := range certificate.Subject.Names {
			if name.Type.String() == oid {
				if value, ok := name.Value.(string); ok {
					return strings.TrimSpace(value)
				}
			}
		}
		return ""
	}
	given, surname := attribute("2.5.4.42"), attribute("2.5.4.4")
	name := strings.TrimSpace(given + " " + surname)
	if name == "" {
		name = strings.TrimSpace(certificate.Subject.CommonName)
	}
	identifier := strings.TrimSpace(certificate.Subject.SerialNumber)
	if identifier == "" {
		identifier = attribute("2.5.4.97")
	}
	return Holder{Name: name, Identifier: identifier}
}
