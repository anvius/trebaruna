package domain

import (
	"crypto/x509"
	"time"
)

// UsableForSigning reports whether a certificate can sign a document at the
// given time: it is within its validity, it is not a certificate authority's,
// and its key usage names a signature (digitalSignature or nonRepudiation).
//
// A store or a card also holds certificate authorities' roots and expired
// certificates, which never sign a document; the listings do not offer them.
func UsableForSigning(certificate *x509.Certificate, now time.Time) bool {
	if certificate == nil || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return false
	}
	if certificate.BasicConstraintsValid && certificate.IsCA {
		return false
	}
	return certificate.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) != 0
}
