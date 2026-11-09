// Package publickey reads the public key of a certificate where crypto/x509
// does not: an RSA key published as id-RSASSA-PSS (RFC 4055), which it
// leaves nil. German qualified authorities (D-TRUST CA 3-1 2016, the HBA
// health-professional CAs) and the German trusted list's signer have one.
package publickey

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// OIDRSASSAPSS is id-RSASSA-PSS: as a key, an RSA key restricted to PSS; as
// a signature algorithm, RSASSA-PSS with its parameters.
var OIDRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

// Of is the key a certificate's signatures are checked with: its public key,
// or the RSA key it publishes as id-RSASSA-PSS.
func Of(certificate *x509.Certificate) crypto.PublicKey {
	if certificate.PublicKey != nil {
		return certificate.PublicKey
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(certificate.RawSubjectPublicKeyInfo, &info)
	if err != nil || len(rest) > 0 || !info.Algorithm.Algorithm.Equal(OIDRSASSAPSS) {
		return nil
	}
	key, err := x509.ParsePKCS1PublicKey(info.PublicKey.RightAlign())
	if err != nil {
		return nil
	}
	return key
}

// Complete fills in the key of certificates that publish it as
// id-RSASSA-PSS, so that crypto/x509 checks what they sign: a chain through
// such an authority. The others are left as they are.
func Complete(certificates ...*x509.Certificate) {
	for _, certificate := range certificates {
		if certificate == nil || certificate.PublicKey != nil {
			continue
		}
		if key := Of(certificate); key != nil {
			certificate.PublicKey, certificate.PublicKeyAlgorithm = key, x509.RSA
		}
	}
}
