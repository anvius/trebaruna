package infrastructure

// Minimal XMLDSig verification for trust lists.
//
// It covers what the lists use: one enveloped signature, exclusive or inclusive
// c14n, SHA-256 digests, RSA or ECDSA signature over SignedInfo. Anything else is
// reported instead of guessed.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/beevik/etree"
)

// OIDs and algorithm identifiers used by XMLDSig.
const (
	xmlsigNamespace = "http://www.w3.org/2000/09/xmldsig#"

	algExclusiveC14N      = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algInclusiveC14N      = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	algEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algSHA256             = "http://www.w3.org/2001/04/xmlenc#sha256"
	algSHA1               = "http://www.w3.org/2000/09/xmldsig#sha1"
	algSHA384             = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	algSHA512             = "http://www.w3.org/2001/04/xmlenc#sha512"
	algRSASHA256          = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algECDSASHA256        = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	algRSASHA1            = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	algRSASHA512          = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	algECDSASHA512        = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

// verifyXMLSignature checks the enveloped signature against a certificate.
func verifyXMLSignature(root *etree.Element, cert *x509.Certificate) error {
	signature := findElement(root, "Signature", xmlsigNamespace)
	if signature == nil {
		return fmt.Errorf("no signature element")
	}

	signedInfo := findElement(signature, "SignedInfo", xmlsigNamespace)
	if signedInfo == nil {
		return fmt.Errorf("no SignedInfo")
	}

	// 1. Verify every reference digest.
	references := findAll(signedInfo, "Reference", xmlsigNamespace)
	if len(references) == 0 {
		return fmt.Errorf("SignedInfo has no references")
	}
	for _, reference := range references {
		if err := verifyReference(root, signature, reference); err != nil {
			return err
		}
	}

	// 2. Canonicalise SignedInfo exactly as declared and verify the signature.
	method := findElement(signedInfo, "CanonicalizationMethod", xmlsigNamespace)
	canonical, err := canonicalizeByAlgorithm(signedInfo, method)
	if err != nil {
		return err
	}

	signatureValueElement := findElement(signature, "SignatureValue", xmlsigNamespace)
	if signatureValueElement == nil {
		return fmt.Errorf("no SignatureValue")
	}
	signatureValue, err := base64.StdEncoding.DecodeString(cleanBase64(signatureValueElement.Text()))
	if err != nil {
		return fmt.Errorf("SignatureValue is not base64: %w", err)
	}

	algorithm := ""
	if element := findElement(signedInfo, "SignatureMethod", xmlsigNamespace); element != nil {
		algorithm = element.SelectAttrValue("Algorithm", "")
	}

	digest := crypto.SHA256
	switch algorithm {
	case algRSASHA1:
		digest = crypto.SHA1
	case algRSASHA256, algECDSASHA256:
		digest = crypto.SHA256
	case "", algECDSASHA512, algRSASHA512:
		digest = crypto.SHA512
	default:
		return fmt.Errorf("unsupported signature method %q", algorithm)
	}

	hasher := digest.New()
	hasher.Write(canonical)
	hashed := hasher.Sum(nil)

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, digest, hashed, signatureValue); err != nil {
			return fmt.Errorf("RSA signature does not verify: %w", err)
		}
	case *ecdsa.PublicKey:
		// XMLDSig encodes an ECDSA signature as the raw concatenation r||s, not
		// as the ASN.1 SEQUENCE that VerifyASN1 expects. Passing the raw form to
		// VerifyASN1 made every ECDSA-signed list fail with a message that looked
		// like a broken signature.
		if err := verifyECDSAXMLDSig(key, hashed, signatureValue); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported public key type %T", cert.PublicKey)
	}

	return nil
}

// digestAlgorithmFor maps an XMLDSig digest URI onto a crypto.Hash.
//
// SHA-512 matters more than it looks: most European trust lists sign with it, so
// supporting only SHA-256 rejected the majority of them for the wrong reason.
func digestAlgorithmFor(algorithm string) (crypto.Hash, error) {
	switch algorithm {
	case algSHA256:
		return crypto.SHA256, nil
	case algSHA384:
		return crypto.SHA384, nil
	case algSHA512:
		return crypto.SHA512, nil
	case algSHA1:
		return crypto.SHA1, nil
	}
	return 0, fmt.Errorf("unsupported digest algorithm %q", algorithm)
}

// verifyReference recomputes one reference digest.
func verifyReference(root, signature, reference *etree.Element) error {
	uri := reference.SelectAttrValue("URI", "")
	transforms := findAll(findElement(reference, "Transforms", xmlsigNamespace), "Transform", xmlsigNamespace)

	// Which element is being digested.
	// The element is canonicalised in place, never as a detached copy: exclusive
	// c14n resolves prefixes through the ancestor chain, and a copy has none, so
	// "undeclared namespace prefix: xades" was the result of detaching it.
	var target *etree.Element
	switch {
	case uri == "":
		// The whole document, minus the signature when the enveloped transform
		// is declared. The signature is removed from a copy of the tree, which is
		// the one case where copying is safe: the root carries its declarations.
		target = root.Copy()
		for _, transform := range transforms {
			if transform.SelectAttrValue("Algorithm", "") == algEnvelopedSignature {
				removeSignature(target)
			}
		}
	case len(uri) > 1 && uri[0] == '#':
		target = findByAttr(root, "Id", uri[1:])
		if target == nil {
			return fmt.Errorf("reference %q does not resolve", uri)
		}
	default:
		return fmt.Errorf("unsupported reference URI %q", uri)
	}

	// Apply the c14n transform the reference declares, if any.
	canonical, err := canonicalizeWithTransforms(target, transforms)
	if err != nil {
		return err
	}

	digestAlgorithm := algSHA256
	if element := findElement(reference, "DigestMethod", xmlsigNamespace); element != nil {
		digestAlgorithm = element.SelectAttrValue("Algorithm", algSHA256)
	}

	digest, err := digestAlgorithmFor(digestAlgorithm)
	if err != nil {
		return err
	}

	declaredElement := findElement(reference, "DigestValue", xmlsigNamespace)
	if declaredElement == nil {
		return fmt.Errorf("reference has no DigestValue")
	}
	declared, err := base64.StdEncoding.DecodeString(cleanBase64(declaredElement.Text()))
	if err != nil {
		return fmt.Errorf("DigestValue is not base64: %w", err)
	}

	hasher := digest.New()
	hasher.Write(canonical)
	if !bytes.Equal(hasher.Sum(nil), declared) {
		return fmt.Errorf("digest mismatch for reference %q", uri)
	}
	return nil
}

// canonicalizeByAlgorithm canonicalises an element using a declared method.
func canonicalizeByAlgorithm(element, method *etree.Element) ([]byte, error) {
	algorithm := ""
	if method != nil {
		algorithm = method.SelectAttrValue("Algorithm", "")
	}
	switch algorithm {
	case "", algExclusiveC14N:
		return CanonicalizeExclusiveInContext(element)
	case algInclusiveC14N:
		// Inclusive c14n keeps every in-scope namespace; the exclusive
		// implementation is the wrong tool, so this is refused rather than
		// returning a digest nobody else would reproduce.
		return nil, fmt.Errorf("%w: inclusive c14n", errUnsupportedC14N)
	}
	return nil, fmt.Errorf("unsupported canonicalisation %q", algorithm)
}

// canonicalizeWithTransforms applies the c14n transform from a reference.
func canonicalizeWithTransforms(element *etree.Element, transforms []*etree.Element) ([]byte, error) {
	algorithm := ""
	for _, transform := range transforms {
		candidate := transform.SelectAttrValue("Algorithm", "")
		if candidate == algExclusiveC14N || candidate == algInclusiveC14N {
			algorithm = candidate
		}
	}

	switch algorithm {
	case "", algExclusiveC14N:
		return CanonicalizeExclusiveInContext(element)
	case algInclusiveC14N:
		return nil, fmt.Errorf("%w: inclusive c14n", errUnsupportedC14N)
	}
	return nil, fmt.Errorf("unsupported transform %q", algorithm)
}

// removeSignature deletes the ds:Signature subtree from a copy of the document.
func removeSignature(element *etree.Element) {
	for _, child := range element.ChildElements() {
		if child.Tag == "Signature" && child.NamespaceURI() == xmlsigNamespace {
			element.RemoveChild(child)
			return
		}
		removeSignature(child)
	}
}

// findAll returns every matching descendant.
func findAll(root *etree.Element, local, namespace string) []*etree.Element {
	var found []*etree.Element
	if root == nil {
		return found
	}
	walkElements(root, func(element *etree.Element) {
		if element.Tag == local && element.NamespaceURI() == namespace {
			found = append(found, element)
		}
	})
	return found
}

// findByAttr returns the first descendant with an attribute value.
func findByAttr(root *etree.Element, key, value string) *etree.Element {
	var found *etree.Element
	walkElements(root, func(element *etree.Element) {
		if found != nil {
			return
		}
		if element.SelectAttrValue(key, "") == value {
			found = element
		}
	})
	return found
}

// cleanBase64 removes whitespace from base64 text.
func cleanBase64(text string) string {
	var builder bytes.Buffer
	for _, character := range text {
		switch character {
		case ' ', '\n', '\r', '\t':
			continue
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

// verifyECDSAXMLDSig checks the r||s encoding XMLDSig uses for ECDSA.
func verifyECDSAXMLDSig(key *ecdsa.PublicKey, hashed, signature []byte) error {
	size := (key.Curve.Params().BitSize + 7) / 8

	// Some producers emit the ASN.1 form anyway; accept both rather than reject a
	// valid signature over an encoding detail.
	if len(signature) != 2*size {
		if ecdsa.VerifyASN1(key, hashed, signature) {
			return nil
		}
		return fmt.Errorf("ECDSA signature does not verify (unexpected length %d, want %d)",
			len(signature), 2*size)
	}

	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])

	if !ecdsa.Verify(key, hashed, r, s) {
		return fmt.Errorf("ECDSA signature does not verify")
	}
	return nil
}
