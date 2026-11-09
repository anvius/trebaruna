package infrastructure

import (
	"bytes"
	"crypto/x509"
	"strings"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// describeSigningCertificate checks the certificate a XAdES signature names
// in its signed properties (SigningCertificate or SigningCertificateV2,
// EN 319 132-1 5.2.2) against the one KeyInfo carries. The value over
// SignedInfo proves the key; this proves the identity: without it a
// certificate with the same key and another name could be put in KeyInfo.
// The signed properties count only when SignedInfo references them.
func describeSigningCertificate(signature *etree.Element, certificate *x509.Certificate, report *domain.SignerReport) {
	if certificate == nil || !hasQualifyingProperties(signature) {
		return
	}
	var digests []namedDigest
	if properties := signedProperties(signature); properties != nil {
		digests = certificateDigests(properties)
	}
	matches := false
	for _, named := range digests {
		if digest, err := xmldsig.Digest(named.algorithm, certificate.Raw); err == nil && bytes.Equal(digest, named.value) {
			matches = true
		}
	}
	reportSigningCertificate(len(digests) > 0, matches, report)
}

// namedDigest is a certificate digest from the signed properties.
type namedDigest struct {
	algorithm string
	value     []byte
}

// signedProperties finds the signature's SignedProperties, when SignedInfo
// references them by Id.
func signedProperties(signature *etree.Element) *etree.Element {
	referenced := map[string]bool{}
	for _, reference := range signature.FindElements("./SignedInfo/Reference") {
		if uri := reference.SelectAttrValue("URI", ""); strings.HasPrefix(uri, "#") {
			referenced[uri[1:]] = true
		}
	}
	var found *etree.Element
	walk(signature, func(element *etree.Element) {
		if found == nil && element.Tag == "SignedProperties" && strings.HasPrefix(element.NamespaceURI(), "http://uri.etsi.org/01903/") &&
			referenced[element.SelectAttrValue("Id", "")] {
			found = element
		}
	})
	return found
}

func hasQualifyingProperties(signature *etree.Element) bool {
	return xmlSignatureFormat(signature) == "XAdES"
}

// certificateDigests reads the Cert/CertDigest entries of SigningCertificate
// and SigningCertificateV2.
func certificateDigests(properties *etree.Element) []namedDigest {
	var digests []namedDigest
	walk(properties, func(element *etree.Element) {
		if element.Tag != "SigningCertificate" && element.Tag != "SigningCertificateV2" {
			return
		}
		walk(element, func(digest *etree.Element) {
			if digest.Tag != "CertDigest" {
				return
			}
			method, value := childElement(digest, "DigestMethod"), childElement(digest, "DigestValue")
			if method == nil || value == nil {
				return
			}
			digests = append(digests, namedDigest{algorithm: method.SelectAttrValue("Algorithm", ""), value: decodeBase64Element(value.Text())})
		})
	})
	return digests
}

func childElement(element *etree.Element, tag string) *etree.Element {
	for _, child := range element.ChildElements() {
		if child.Tag == tag {
			return child
		}
	}
	return nil
}
