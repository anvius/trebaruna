package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1" // XML signatures made before 2015 use SHA-1; they are still checked
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/beevik/etree"
)

var (
	// ErrModified means the signature does not match what it signs: a digest
	// or the signature value differs.
	ErrModified = errors.New("the XML signature does not match what it signs")
	// ErrUnverifiable means the signature uses an algorithm or a transform
	// trebaruna does not implement, so it can say neither yes nor no.
	ErrUnverifiable = errors.New("the XML signature cannot be checked here")
	// ErrContentMissing means a reference points at content outside the
	// document that is not available.
	ErrContentMissing = errors.New("the signed content is not available")
)

// Resolver returns the bytes a reference outside the document points at,
// such as the file a detached signature signs, or an error wrapping
// ErrContentMissing.
type Resolver func(uri string) ([]byte, error)

// digests are the reference digest algorithms.
var digests = map[string]crypto.Hash{
	"http://www.w3.org/2000/09/xmldsig#sha1":        crypto.SHA1,
	"http://www.w3.org/2001/04/xmldsig-more#sha224": crypto.SHA224,
	"http://www.w3.org/2001/04/xmlenc#sha256":       crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": crypto.SHA384,
	"http://www.w3.org/2001/04/xmlenc#sha512":       crypto.SHA512,
}

// signatureMethod is a SignatureMethod: the digest and the key it needs.
type signatureMethod struct {
	hash  crypto.Hash
	ecdsa bool
}

var signatureMethods = map[string]signatureMethod{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":          {crypto.SHA1, false},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha224":   {crypto.SHA224, false},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   {crypto.SHA256, false},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   {crypto.SHA384, false},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   {crypto.SHA512, false},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1":   {crypto.SHA1, true},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224": {crypto.SHA224, true},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": {crypto.SHA256, true},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": {crypto.SHA384, true},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": {crypto.SHA512, true},
}

// Check verifies an XML signature completely (XML-Signature 3.2): every
// reference of SignedInfo is dereferenced, transformed and digested, then the
// signature value over the canonical SignedInfo is checked with key. A
// mismatch anywhere wins over what cannot be checked.
func Check(document *etree.Document, signature *etree.Element, key crypto.PublicKey, resolve Resolver) error {
	signedInfo := child(signature, "SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("%w: no SignedInfo", ErrModified)
	}
	references := children(signedInfo, "Reference")
	if len(references) == 0 {
		return fmt.Errorf("%w: SignedInfo references nothing", ErrModified)
	}

	var problems []error
	for _, reference := range references {
		if err := checkReference(document, signature, reference, resolve); err != nil {
			problems = append(problems, fmt.Errorf("reference %q: %w", reference.SelectAttrValue("URI", ""), err))
		}
	}
	if err := checkSignatureValue(signature, signedInfo, key); err != nil {
		problems = append(problems, err)
	}
	for _, problem := range problems {
		if errors.Is(problem, ErrModified) {
			return problem
		}
	}
	if len(problems) > 0 {
		return problems[0]
	}
	return nil
}

// checkReference compares a reference's DigestValue with the digest of what
// it points at.
func checkReference(document *etree.Document, signature, reference *etree.Element, resolve Resolver) error {
	method, value := child(reference, "DigestMethod"), child(reference, "DigestValue")
	if method == nil || value == nil {
		return fmt.Errorf("%w: incomplete reference", ErrModified)
	}
	hash, known := digests[method.SelectAttrValue("Algorithm", "")]
	if !known {
		return fmt.Errorf("%w: digest %s", ErrUnverifiable, method.SelectAttrValue("Algorithm", ""))
	}
	declared, err := decodeBase64(textOf(value))
	if err != nil {
		return fmt.Errorf("%w: the digest is not Base64", ErrModified)
	}
	data, err := ReferenceData(document, signature, reference, resolve)
	if err != nil {
		return err
	}
	digest := hash.New()
	digest.Write(data)
	if !bytes.Equal(digest.Sum(nil), declared) {
		return fmt.Errorf("%w: the digest differs", ErrModified)
	}
	return nil
}

// nodeSet is what a same-document reference selects: a copy of the whole
// document, so namespaces resolve as in the original, and the element the
// reference names (nil for the whole document).
type nodeSet struct {
	document *etree.Document
	apex     *etree.Element
}

// scope is the element the node-set covers.
func (s nodeSet) scope() *etree.Element {
	if s.apex != nil {
		return s.apex
	}
	return s.document.Root()
}

// ReferenceData returns the octets a reference digests: its URI resolved and
// its transforms applied (XML-Signature 4.4.3). A signer digests them to fill
// DigestValue; an archive timestamp covers them (EN 319 132-1, 5.5.2.2).
func ReferenceData(document *etree.Document, signature, reference *etree.Element, resolve Resolver) ([]byte, error) {
	attribute := reference.SelectAttr("URI")
	if attribute == nil {
		return nil, fmt.Errorf("%w: a reference without URI", ErrUnverifiable)
	}
	uri := attribute.Value
	transforms := children(child(reference, "Transforms"), "Transform")
	switch {
	case strings.HasPrefix(uri, "#xpointer("):
		return nil, fmt.Errorf("%w: XPointer references", ErrUnverifiable)
	case uri != "" && !strings.HasPrefix(uri, "#"):
		return external(uri, transforms, resolve)
	}

	set := nodeSet{document: document.Copy()}
	if uri != "" {
		apex, err := elementByID(set.document.Root(), uri[1:])
		if err != nil {
			return nil, err
		}
		set.apex = apex
	}
	signatureCopy := follow(&set.document.Element, pathTo(signature))

	for index, transform := range transforms {
		algorithm := transform.SelectAttrValue("Algorithm", "")
		switch {
		case algorithm == EnvelopedSignature:
			if signatureCopy != nil && signatureCopy.Parent() != nil {
				signatureCopy.Parent().RemoveChild(signatureCopy)
			}
		case algorithm == XPathTransform:
			if !excludesSignatures(transform) {
				return nil, fmt.Errorf("%w: XPath expression %q", ErrUnverifiable, strings.TrimSpace(textOf(child(transform, "XPath"))))
			}
			removeSignatures(set.scope())
		case algorithm == Base64Transform:
			decoded, err := decodeBase64(stringValue(set.scope()))
			if err != nil {
				return nil, fmt.Errorf("%w: the Base64 content does not decode", ErrModified)
			}
			return octetTransforms(decoded, transforms[index+1:])
		case IsCanonicalization(algorithm):
			canonical, err := canonicalizeSet(set, algorithm, prefixList(transform))
			if err != nil {
				return nil, err
			}
			return octetTransforms(canonical, transforms[index+1:])
		default:
			return nil, fmt.Errorf("%w: transform %s", ErrUnverifiable, algorithm)
		}
	}
	return canonicalizeSet(set, C14N10, "")
}

// canonicalizeSet turns a same-document node-set into octets; such a
// reference has already dropped its comments.
func canonicalizeSet(set nodeSet, algorithm, prefixes string) ([]byte, error) {
	if plain, ok := withoutComments[algorithm]; ok {
		algorithm = plain
	}
	if set.apex == nil {
		return CanonicalizeDocument(set.document, algorithm, prefixes)
	}
	return Canonicalize(set.apex, algorithm, prefixes)
}

// external resolves a reference to content outside the document, such as
// the file a detached signature signs, and applies the transforms octets
// take.
func external(uri string, transforms []*etree.Element, resolve Resolver) ([]byte, error) {
	if resolve == nil {
		return nil, fmt.Errorf("%w: %s", ErrContentMissing, uri)
	}
	content, err := resolve(uri)
	if err != nil {
		return nil, err
	}
	return octetTransforms(content, transforms)
}

// octetTransforms applies the transforms that take octets: Base64 decoding,
// and canonicalisation of octets that are an XML document.
func octetTransforms(octets []byte, transforms []*etree.Element) ([]byte, error) {
	for _, transform := range transforms {
		algorithm := transform.SelectAttrValue("Algorithm", "")
		switch {
		case algorithm == Base64Transform:
			decoded, err := decodeBase64(string(octets))
			if err != nil {
				return nil, fmt.Errorf("%w: the Base64 content does not decode", ErrModified)
			}
			octets = decoded
		case IsCanonicalization(algorithm):
			parsed := etree.NewDocument()
			if err := parsed.ReadFromBytes(octets); err != nil {
				return nil, fmt.Errorf("%w: the signed content is not XML", ErrModified)
			}
			canonical, err := CanonicalizeDocument(parsed, algorithm, prefixList(transform))
			if err != nil {
				return nil, err
			}
			octets = canonical
		default:
			return nil, fmt.Errorf("%w: transform %s on octets", ErrUnverifiable, algorithm)
		}
	}
	return octets, nil
}

// checkSignatureValue checks SignatureValue over the canonical SignedInfo.
// ECDSA values are read as r||s (RFC 6931) or, as some producers write them,
// ASN.1.
func checkSignatureValue(signature, signedInfo *etree.Element, key crypto.PublicKey) error {
	canonicalization := child(signedInfo, "CanonicalizationMethod")
	signatureMethodElement := child(signedInfo, "SignatureMethod")
	valueElement := child(signature, "SignatureValue")
	if canonicalization == nil || signatureMethodElement == nil || valueElement == nil {
		return fmt.Errorf("%w: incomplete SignedInfo", ErrModified)
	}
	method, known := signatureMethods[signatureMethodElement.SelectAttrValue("Algorithm", "")]
	if !known {
		return fmt.Errorf("%w: signature method %s", ErrUnverifiable, signatureMethodElement.SelectAttrValue("Algorithm", ""))
	}
	canonical, err := Canonicalize(signedInfo, canonicalization.SelectAttrValue("Algorithm", ""), prefixList(canonicalization))
	if err != nil {
		return err
	}
	value, err := decodeBase64(textOf(valueElement))
	if err != nil {
		return fmt.Errorf("%w: the signature value is not Base64", ErrModified)
	}
	digest := method.hash.New()
	digest.Write(canonical)
	sum := digest.Sum(nil)

	switch public := key.(type) {
	case *rsa.PublicKey:
		if method.ecdsa || rsa.VerifyPKCS1v15(public, method.hash, sum, value) != nil {
			return fmt.Errorf("%w: the signature value does not verify", ErrModified)
		}
	case *ecdsa.PublicKey:
		size := (public.Curve.Params().BitSize + 7) / 8
		var valid bool
		if len(value) == 2*size {
			valid = ecdsa.Verify(public, sum, new(big.Int).SetBytes(value[:size]), new(big.Int).SetBytes(value[size:]))
		} else {
			valid = ecdsa.VerifyASN1(public, sum, value)
		}
		if !method.ecdsa || !valid {
			return fmt.Errorf("%w: the signature value does not verify", ErrModified)
		}
	default:
		return fmt.Errorf("%w: a %T key", ErrUnverifiable, key)
	}
	return nil
}

// elementByID finds the one element whose Id (or ID, or id) is id; two
// carrying it is how wrapping attacks start, and is refused.
func elementByID(root *etree.Element, id string) (*etree.Element, error) {
	var found []*etree.Element
	var visit func(*etree.Element)
	visit = func(element *etree.Element) {
		for _, name := range []string{"Id", "ID", "id"} {
			if element.SelectAttrValue(name, "\x00") == id {
				found = append(found, element)
				break
			}
		}
		for _, childElement := range element.ChildElements() {
			visit(childElement)
		}
	}
	visit(root)
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: nothing carries Id %q", ErrModified, id)
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("%w: %d elements carry Id %q", ErrModified, len(found), id)
}

// signatureFilter is the XPath transform that leaves every signature out of
// the node-set, the one AutoFirma and most producers write.
var signatureFilter = regexp.MustCompile(`^not\(ancestor-or-self::([A-Za-z_][\w.-]*):Signature\)$`)

// excludesSignatures reports an XPath transform whose expression is the
// signature filter, its prefix bound to the XML-Signature namespace.
func excludesSignatures(transform *etree.Element) bool {
	expression := child(transform, "XPath")
	if expression == nil {
		return false
	}
	match := signatureFilter.FindStringSubmatch(strings.Join(strings.Fields(textOf(expression)), ""))
	return match != nil && lookupNamespace(expression, match[1]) == Namespace
}

// removeSignatures removes every XML signature within element.
func removeSignatures(element *etree.Element) {
	for _, childElement := range element.ChildElements() {
		if childElement.Tag == "Signature" && childElement.NamespaceURI() == Namespace {
			element.RemoveChild(childElement)
			continue
		}
		removeSignatures(childElement)
	}
}

// lookupNamespace resolves a prefix where element stands.
func lookupNamespace(element *etree.Element, prefix string) string {
	for current := element; current != nil; current = current.Parent() {
		for _, attribute := range current.Attr {
			if attribute.Space == "xmlns" && attribute.Key == prefix {
				return attribute.Value
			}
		}
	}
	return ""
}

// pathTo is the position of element from its document, child by child.
func pathTo(element *etree.Element) []int {
	var path []int
	for current := element; current.Parent() != nil; current = current.Parent() {
		path = append([]int{current.Index()}, path...)
	}
	return path
}

// follow walks a path from pathTo in another copy of the document.
func follow(start *etree.Element, path []int) *etree.Element {
	current := start
	for _, index := range path {
		if index < 0 || index >= len(current.Child) {
			return nil
		}
		next, ok := current.Child[index].(*etree.Element)
		if !ok {
			return nil
		}
		current = next
	}
	return current
}

// stringValue is the text an element holds, its descendants' included.
func stringValue(element *etree.Element) string {
	var text strings.Builder
	for _, token := range element.Child {
		switch typed := token.(type) {
		case *etree.CharData:
			text.WriteString(typed.Data)
		case *etree.Element:
			text.WriteString(stringValue(typed))
		}
	}
	return text.String()
}

// prefixList is the InclusiveNamespaces PrefixList of exclusive C14N.
func prefixList(element *etree.Element) string {
	for _, childElement := range element.ChildElements() {
		if childElement.Tag == "InclusiveNamespaces" {
			return childElement.SelectAttrValue("PrefixList", "")
		}
	}
	return ""
}

// child is the first XML-Signature child element with the tag.
func child(element *etree.Element, tag string) *etree.Element {
	if found := children(element, tag); len(found) > 0 {
		return found[0]
	}
	return nil
}

// children are the XML-Signature child elements with the tag.
func children(element *etree.Element, tag string) []*etree.Element {
	if element == nil {
		return nil
	}
	var found []*etree.Element
	for _, childElement := range element.ChildElements() {
		if childElement.Tag == tag && childElement.NamespaceURI() == Namespace {
			found = append(found, childElement)
		}
	}
	return found
}

// textOf is an element's text, empty for none.
func textOf(element *etree.Element) string {
	if element == nil {
		return ""
	}
	return stringValue(element)
}

// decodeBase64 decodes Base64 written across lines.
func decodeBase64(text string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
}
