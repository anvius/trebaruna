package infrastructure

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// The ESS attributes that name a CMS signer's certificate.
var (
	oidAttributeSigningCertificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttributeSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

// essDigest is a certificate digest an ESS attribute gives.
type essDigest struct {
	hash  crypto.Hash
	value []byte
}

// essCertificateDigests reads the certificate digests a signer names in its
// signed attributes: signing-certificate-v2 (RFC 5035, SHA-256 unless it
// says otherwise) and signing-certificate (RFC 2634, SHA-1). The signer's
// identifier is not signed; these attributes are what bind the certificate.
func essCertificateDigests(signedAttributes asn1.RawValue) []essDigest {
	var digests []essDigest
	read := func(oid asn1.ObjectIdentifier, versionTwo bool) {
		for _, value := range attributeValues(signedAttributes, oid) {
			var outer, certificates asn1.RawValue
			if _, err := asn1.Unmarshal(value, &outer); err != nil {
				continue
			}
			if _, err := asn1.Unmarshal(outer.Bytes, &certificates); err != nil {
				continue
			}
			for rest := certificates.Bytes; len(rest) > 0; {
				var identifier asn1.RawValue
				var err error
				if rest, err = asn1.Unmarshal(rest, &identifier); err != nil {
					break
				}
				if digest, ok := essIdentifier(identifier.Bytes, versionTwo); ok {
					digests = append(digests, digest)
				}
			}
		}
	}
	read(oidAttributeSigningCertificateV2, true)
	read(oidAttributeSigningCertificate, false)
	return digests
}

// essIdentifier reads an ESSCertIDv2 ([AlgorithmIdentifier] certHash …) or
// an ESSCertID (certHash …).
func essIdentifier(content []byte, versionTwo bool) (essDigest, bool) {
	hash := crypto.SHA1
	if versionTwo {
		hash = crypto.SHA256
	}
	var first asn1.RawValue
	rest, err := asn1.Unmarshal(content, &first)
	if err != nil {
		return essDigest{}, false
	}
	if versionTwo && first.Tag == asn1.TagSequence {
		var algorithm pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(first.FullBytes, &algorithm); err != nil {
			return essDigest{}, false
		}
		known := false
		if hash, known = digestFromOID(algorithm.Algorithm); !known {
			return essDigest{}, false
		}
		if _, err := asn1.Unmarshal(rest, &first); err != nil {
			return essDigest{}, false
		}
	}
	if first.Tag != asn1.TagOctetString {
		return essDigest{}, false
	}
	return essDigest{hash: hash, value: first.Bytes}, true
}

// essMatches reports whether a certificate is one the digests name.
func essMatches(digests []essDigest, certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	for _, digest := range digests {
		if !digest.hash.Available() {
			continue
		}
		hasher := digest.hash.New()
		hasher.Write(certificate.Raw)
		if bytes.Equal(hasher.Sum(nil), digest.value) {
			return true
		}
	}
	return false
}

// describeESSCertificate reports whether the certificate shown is the one
// the CMS signer named.
func describeESSCertificate(digests []essDigest, certificate *x509.Certificate, report *domain.SignerReport) {
	if certificate == nil || report.Integrity != domain.StatusGood {
		return
	}
	reportSigningCertificate(len(digests) > 0, essMatches(digests, certificate), report)
}

// chooseSigner picks, among the certificates answering to a signer's
// identifier, one whose key verifies: the one the signed ESS attribute
// names when there is one. With none verifying, the first and its error.
func chooseSigner(candidates []*x509.Certificate, named []essDigest, verify func(*x509.Certificate) error) (*x509.Certificate, error) {
	var verified *x509.Certificate
	for _, candidate := range candidates {
		if verify(candidate) != nil {
			continue
		}
		if essMatches(named, candidate) {
			return candidate, nil
		}
		if verified == nil {
			verified = candidate
		}
	}
	switch {
	case verified != nil:
		return verified, nil
	case len(candidates) > 0:
		return candidates[0], verify(candidates[0])
	}
	return nil, errors.New("the signing certificate is not in the envelope")
}

// reportSigningCertificate records the binding: bound; a mismatch, which
// breaks the signature, for the identity shown was not signed; or no
// certificate named at all.
func reportSigningCertificate(named, matches bool, report *domain.SignerReport) {
	switch {
	case !named:
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signing_certificate.missing",
			Status:  domain.StatusWarn,
			Message: "the signature names no signing certificate in its signed properties: the certificate shown is not bound to it",
		})
	case matches:
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signing_certificate.bound",
			Status:  domain.StatusGood,
			Message: "the certificate shown is the one the signature names",
		})
	default:
		report.Integrity = domain.StatusBad
		report.Findings = append(withoutFinding(report.Findings, "signature.intact"), domain.Finding{
			Code:    "signing_certificate.mismatch",
			Status:  domain.StatusBad,
			Message: "the certificate shown is not the one the signature names: the identity it gives was not signed",
		})
	}
}
