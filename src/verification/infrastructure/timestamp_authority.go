// This file prepares the timestamp token for the trust decision.
//
// The cryptographic verification of the token already happens when it is parsed:
// the timestamp library checks the CMS signature against the certificates the
// token carries, and the imprint is compared with this signature's own value.
// What remains is the question the token cannot answer about itself: is the
// authority that sealed it a qualified one? That needs the trust list, so this
// file only assembles the facts and the use case decides.

package infrastructure

import (
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/digitorus/timestamp"
)

// oidExtendedKeyUsage is the extension that must contain id-kp-timeStamping.
var oidExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// oidTimeStamping is the key purpose a qualified timestamp certificate needs.
var oidTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

// TimestampFacts describes the authority behind a parsed token.
type TimestampFacts struct {
	// Certificates are every certificate the token carries.
	Certificates []*x509.Certificate
	// Signer is the certificate that produced the token's signature: the first
	// one, because the TSA places its own certificate first.
	Signer *x509.Certificate
	// SignerIssuerDN is the subject of the CA that issued the signer, which is
	// what a list publishing the authority's CA will contain.
	SignerIssuerDN string
	// CanTimestamp reports the id-kp-timeStamping extended key usage, which
	// ETSI EN 319 412-4 requires and marks critical.
	CanTimestamp bool
	// Time is the instant the token claims.
	Time time.Time
}

// ReadTimestamp describes the token's authority without judging it.
func ReadTimestamp(token *timestamp.Timestamp) TimestampFacts {
	if token == nil {
		return TimestampFacts{}
	}

	facts := TimestampFacts{
		Certificates: token.Certificates,
		Time:         token.Time,
	}
	if len(token.Certificates) == 0 {
		return facts
	}

	facts.Signer = token.Certificates[0]
	facts.SignerIssuerDN = facts.Signer.Issuer.String()
	facts.CanTimestamp = hasTimeStampingUsage(facts.Signer)
	return facts
}

// hasTimeStampingUsage reports whether the certificate carries id-kp-timeStamping.
//
// The extension is parsed by hand rather than read from ExtKeyUsage: a critical
// EKU that Go does not know is kept out of ExtKeyUsage, and a timestamp
// certificate is exactly where that happens. Reading the raw extension avoids
// depending on how the parser classifies an unfamiliar purpose.
func hasTimeStampingUsage(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}

	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidExtendedKeyUsage) {
			continue
		}
		var purposes []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(extension.Value, &purposes); err != nil {
			return false
		}
		for _, purpose := range purposes {
			if purpose.Equal(oidTimeStamping) {
				return true
			}
		}
		return false
	}

	// A certificate that does not restrict its purpose is not a specialised
	// timestamp unit; refusing is the conservative reading.
	return false
}
