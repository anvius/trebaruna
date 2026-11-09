package infrastructure

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	"codeberg.org/simplicer/trebaruna/src/trust/domain"
	"github.com/beevik/etree"
)

// InspectListSignatureWithAnchors verifies a trust list against the
// certificates the LOTL publishes for its territory.
//
// Why it matters: a list is a list of authorities. Anyone who can serve a
// modified copy can insert their own CA, so an unsigned or unverified list is
// inventory, not a trust anchor. The anchor comes from the Commission, not
// from the document being checked: a list signed by an operator whose
// certificate appears in the LOTL for that territory is authenticated;
// anything else stays inventory.
//
// The signature is checked with the same XML-Signature verifier as signed
// documents (xmldsig.Check), and it must sign the whole list (ETSI TS 119 612,
// 5.7.1): a valid signature over one part would leave the rest, where an
// authority can be added, unsigned.
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

	signature := listSignature(document.Root())
	if signature == nil {
		return domain.TrustListIntegrity{Reason: "the list carries no XML signature"}
	}

	certificates := keyInfoCertificates(signature)
	if len(certificates) == 0 {
		return domain.TrustListIntegrity{
			Signed: true,
			Reason: "the signature does not embed its certificate",
		}
	}

	// The signing certificate must be one of the published ones. Comparing the
	// raw DER is exact: a certificate is immutable, so equality is the right
	// test.
	signer := publishedAmong(certificates, anchors)
	if signer == nil {
		return domain.TrustListIntegrity{
			Signed: true,
			Signer: certificates[0].Subject.String(),
			Reason: "the signing certificate is not the one published in the EU list of the lists",
		}
	}

	integrity := domain.TrustListIntegrity{
		Signed: true,
		Signer: signer.Subject.String(),
	}
	if !signsWholeList(document.Root(), signature) {
		integrity.Reason = "the signature does not cover the whole list"
		return integrity
	}
	if err := xmldsig.Check(document, signature, xmldsig.KeyOf(signer), nil); err != nil {
		integrity.Reason = fmt.Sprintf("the signature does not verify: %v", err)
		return integrity
	}

	integrity.SignatureValid = true
	integrity.Trusted = true
	integrity.Reason = "the list is signed by the operator published in the EU list of the lists"
	return integrity
}

// listSignature is the list's own signature: a ds:Signature child of the
// root (ETSI TS 119 612, 5.7). Signatures nested deeper belong to something
// else.
func listSignature(root *etree.Element) *etree.Element {
	if root == nil {
		return nil
	}
	for _, child := range root.ChildElements() {
		if child.Tag == "Signature" && child.NamespaceURI() == xmldsig.Namespace {
			return child
		}
	}
	return nil
}

// signsWholeList reports whether one of the signature's references is the
// whole document: URI="" or the Id of the root.
func signsWholeList(root, signature *etree.Element) bool {
	for _, reference := range signature.FindElements("./SignedInfo/Reference") {
		uri := reference.SelectAttr("URI")
		if uri == nil {
			continue
		}
		if uri.Value == "" {
			return true
		}
		if id, local := strings.CutPrefix(uri.Value, "#"); local {
			if element, err := xmldsig.ElementByID(root, id); err == nil && element == root {
				return true
			}
		}
	}
	return false
}

// keyInfoCertificates reads KeyInfo/X509Data/X509Certificate, in order.
func keyInfoCertificates(signature *etree.Element) []*x509.Certificate {
	var certificates []*x509.Certificate
	for _, element := range signature.FindElements("./KeyInfo/X509Data/X509Certificate") {
		if element.NamespaceURI() != xmldsig.Namespace {
			continue
		}
		if certificate, err := x509.ParseCertificate(decodeBase64Text(element.Text())); err == nil {
			certificates = append(certificates, certificate)
		}
	}
	return certificates
}

// publishedAmong is the first certificate that is one of the anchors.
func publishedAmong(certificates, anchors []*x509.Certificate) *x509.Certificate {
	for _, certificate := range certificates {
		for _, anchor := range anchors {
			if bytes.Equal(anchor.Raw, certificate.Raw) {
				return certificate
			}
		}
	}
	return nil
}

// decodeBase64Text decodes base64 that may contain line breaks.
func decodeBase64Text(text string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil {
		return nil
	}
	return decoded
}
