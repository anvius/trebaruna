package xmldsig

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// oidRSASSAPSS is id-RSASSA-PSS (RFC 4055): an RSA key its certificate
// restricts to PSS signatures.
var oidRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

// KeyOf is the key a certificate's signatures are checked with: its public
// key, or, for an RSA key published as id-RSASSA-PSS, which crypto/x509
// leaves unparsed, that key read from the certificate. The German trusted
// list is signed with one.
func KeyOf(certificate *x509.Certificate) crypto.PublicKey {
	if certificate.PublicKey != nil {
		return certificate.PublicKey
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(certificate.RawSubjectPublicKeyInfo, &info)
	if err != nil || len(rest) > 0 || !info.Algorithm.Algorithm.Equal(oidRSASSAPSS) {
		return nil
	}
	key, err := x509.ParsePKCS1PublicKey(info.PublicKey.RightAlign())
	if err != nil {
		return nil
	}
	return key
}
