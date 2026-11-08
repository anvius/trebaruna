package infrastructure

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"

	"codeberg.org/anvius/pignus/src/trust/domain"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// InspectListSignature checks whether a trust list is signed and whether that
// signature verifies.
//
// Why it matters: a list is a list of authorities. Anyone who can serve a
// modified copy can insert their own CA, so an unsigned or unverified list is
// inventory, not a trust anchor. The check is done here and exposed to the
// caller; the caller decides.
//
// Limitation, stated openly: the signing keys of the national schemes are
// published by the scheme operators, not by the EU, and this package does not
// ship them. So the signature is verified against the certificate embedded in
// the list, which proves integrity of the payload but not provenance. That is
// strictly better than trusting the bytes blindly and strictly worse than
// checking against a pinned key; TrustListIntegrity.Trusted records which one
// happened.
// InspectListSignatureWithAnchors verifies a list against the certificates the
// LOTL publishes for its territory.
//
// This is the check that matters: the anchor comes from the Commission, not from
// the document being checked. A list signed by an operator whose certificate
// appears in the LOTL for that territory is authenticated; anything else stays
// inventory.
func InspectListSignatureWithAnchors(content []byte, anchors []*x509.Certificate) domain.TrustListIntegrity {
	if len(anchors) == 0 {
		return domain.TrustListIntegrity{
			Reason: "no signing certificate is published for this territory",
		}
	}

	document := etree.NewDocument()
	if err := document.ReadFromBytes(content); err != nil {
		return domain.TrustListIntegrity{Reason: fmt.Sprintf("cannot parse XML: %v", err)}
	}

	signature := findElement(document.Root(), "Signature", signatureNamespace)
	if signature == nil {
		return domain.TrustListIntegrity{Reason: "the list carries no XML signature"}
	}

	embedded := findSigningCertificate(signature)
	if embedded == nil {
		return domain.TrustListIntegrity{
			Signed: true,
			Reason: "the signature does not embed its certificate",
		}
	}

	integrity := domain.TrustListIntegrity{
		Signed: true,
		Signer: embedded.Subject.String(),
	}

	// The embedded certificate must be one of the published ones. Comparing the
	// raw DER is exact: a certificate is immutable, so equality is the right test.
	published := false
	for _, anchor := range anchors {
		if bytes.Equal(anchor.Raw, embedded.Raw) {
			published = true
			break
		}
	}
	if !published {
		integrity.Reason = "the signing certificate is not the one published in the EU list of the lists"
		return integrity
	}

	// The signature is checked here rather than through goxmldsig: that library
	// stops at 1000 namespace traversals, and a national list has far more, so
	// every large list failed with "traversal limit reached" while its signature
	// was perfectly valid.
	if err := verifyXMLSignature(document.Root(), embedded); err != nil {
		integrity.Reason = fmt.Sprintf("the signature does not verify: %v", err)
		return integrity
	}

	integrity.SignatureValid = true
	integrity.Trusted = true
	integrity.Reason = "the list is signed by the operator published in the EU list of the lists"
	return integrity
}

// InspectListSignature verifies a list against a caller-supplied root pool.
//
// Kept for callers that pin roots themselves; the LOTL-anchored variant above is
// what the CLI uses.
func InspectListSignature(content []byte, roots *x509.CertPool) domain.TrustListIntegrity {
	document := etree.NewDocument()
	if err := document.ReadFromBytes(content); err != nil {
		return domain.TrustListIntegrity{Reason: fmt.Sprintf("cannot parse XML: %v", err)}
	}

	signature := findElement(document.Root(), "Signature", signatureNamespace)
	if signature == nil {
		return domain.TrustListIntegrity{Reason: "the list carries no XML signature"}
	}

	certificate := findSigningCertificate(signature)
	if certificate == nil {
		return domain.TrustListIntegrity{
			Signed: true,
			Reason: "the signature does not embed its certificate",
		}
	}

	integrity := domain.TrustListIntegrity{
		Signed: true,
		Signer: certificate.Subject.String(),
	}

	// Integrity of the payload: does the signature match the document?
	store := &listCertificateStore{certificate: certificate}
	context := dsig.NewDefaultValidationContext(store)
	context.IdAttribute = "Id"

	if _, err := context.Validate(document.Root()); err != nil {
		integrity.Reason = fmt.Sprintf("the signature does not verify: %v", err)
		return integrity
	}
	integrity.SignatureValid = true

	// Provenance: does the signing certificate chain to a root we know?
	if roots == nil {
		integrity.Reason = "signature verifies, but no roots were supplied to check the signer"
		return integrity
	}

	intermediates := x509.NewCertPool()
	intermediates.AddCert(certificate)
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		integrity.Reason = "signature verifies, but the signing certificate is not trusted"
		return integrity
	}

	integrity.Trusted = true
	integrity.Reason = "the list is signed and the signing certificate is trusted"
	return integrity
}

// signatureNamespace is the XMLDSig namespace.
const signatureNamespace = "http://www.w3.org/2000/09/xmldsig#"

// findElement walks the tree for an element by local name and namespace.
func findElement(element *etree.Element, local, namespace string) *etree.Element {
	if element == nil {
		return nil
	}
	if element.Tag == local && element.NamespaceURI() == namespace {
		return element
	}
	for _, child := range element.ChildElements() {
		if found := findElement(child, local, namespace); found != nil {
			return found
		}
	}
	return nil
}

// findSigningCertificate reads KeyInfo/X509Data/X509Certificate.
func findSigningCertificate(signature *etree.Element) *x509.Certificate {
	var found *x509.Certificate

	walkElements(signature, func(element *etree.Element) {
		if found != nil || element.Tag != "X509Certificate" || element.NamespaceURI() != signatureNamespace {
			return
		}
		decoded := decodeBase64Text(element.Text())
		if certificate, err := x509.ParseCertificate(decoded); err == nil {
			found = certificate
		}
	})
	return found
}

// walkElements visits every descendant depth-first.
func walkElements(element *etree.Element, visit func(*etree.Element)) {
	if element == nil {
		return
	}
	visit(element)
	for _, child := range element.ChildElements() {
		walkElements(child, visit)
	}
}

// decodeBase64Text decodes base64 that may contain line breaks.
func decodeBase64Text(text string) []byte {
	var buffer bytes.Buffer
	for _, character := range text {
		switch character {
		case ' ', '\n', '\r', '\t':
			continue
		}
		buffer.WriteRune(character)
	}

	decoded, err := base64.StdEncoding.DecodeString(buffer.String())
	if err != nil {
		return nil
	}
	return decoded
}

// listCertificateStore exposes the single certificate that signed the list.
type listCertificateStore struct {
	certificate *x509.Certificate
}

// Certificates returns the embedded signing certificate.
func (s *listCertificateStore) Certificates() ([]*x509.Certificate, error) {
	return []*x509.Certificate{s.certificate}, nil
}

// streamingSignatureScan is a fallback for very large lists where building a
// full etree is wasteful: it only detects presence of a signature.
func streamingSignatureScan(content []byte) bool {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				return false
			}
			return false
		}
		if start, ok := token.(xml.StartElement); ok {
			if start.Name.Local == "Signature" {
				return true
			}
		}
	}
}

var _ = streamingSignatureScan
