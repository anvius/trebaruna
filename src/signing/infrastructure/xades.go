package infrastructure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	"codeberg.org/simplicer/firma-it/src/signing/domain"
	"codeberg.org/simplicer/firma-it/src/signing/infrastructure/cms"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// XadesSigner produces XAdES-BES (ETSI EN 319 132-1).
//
// Digests are computed over real c14n output, produced by goxmldsig's
// canonicalizer and applied to an etree tree. Hashing hand-written strings does
// not work: every verifier re-parses and canonicalises before hashing, so a
// digest taken over the source text never matches.
//
// A third-party XAdES builder was rejected (artemkunich/goxades: 10 stars, no
// commits since 2023), but a canonicalizer is a well-scoped primitive and is
// reused rather than reimplemented.
type XadesSigner struct {
	timestamps Timestamper
}

// NewXadesSigner wires the XML adapter.
func NewXadesSigner(timestamps Timestamper) *XadesSigner {
	return &XadesSigner{timestamps: timestamps}
}

// XAdES constants.
const (
	namespaceDS    = "http://www.w3.org/2000/09/xmldsig#"
	namespaceXades = "http://uri.etsi.org/01903/v1.3.2#"

	algorithmC14N        = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	algorithmEnveloped   = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algorithmSHA256      = "http://www.w3.org/2001/04/xmlenc#sha256"
	algorithmRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algorithmECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	typeSignedProperties = "http://uri.etsi.org/01903#SignedProperties"

	signedPropertiesID  = "firma-it-signed-properties"
	signatureID         = "firma-it-signature"
	documentReferenceID = "firma-it-reference"
	payloadObjectID     = "firma-it-payload"
)

// SignXades signs the document in place (enveloped) or as a payload (enveloping).
//
// Two passes, because the digests must cover the tree exactly as it will be
// read back. Pass one inserts a skeleton with placeholder values; pass two
// canonicalises the real nodes in their final position, fills the digests, and
// signs SignedInfo. Formatting is never touched: re-indenting an element
// changes its text nodes and therefore its digest.
func (s *XadesSigner) SignXades(ctx context.Context, request application.XadesRequest) ([]byte, error) {
	// XAdES-T needs a token over the signature value, which only exists after
	// the signature is computed. Everything else is refused with its reason.
	if request.Level.NeedsTimestamp() && request.TimestampURL == "" {
		return nil, fmt.Errorf(
			"%s for XAdES needs a timestamp authority: pass --tsa <url>",
			request.Level,
		)
	}

	// Accepting LTA and emitting B-T would report a level the file does not have.
	// An archive timestamp is a different structure from the signature one: it
	// covers the whole document, references the existing unsigned properties and
	// has to survive later additions, so it cannot be approximated.
	if request.Level.Archival() {
		return nil, fmt.Errorf(
			"%s for XAdES needs xades:ArchiveTimeStamp, which is not implemented.\n"+
				"  options:\n"+
				"    --level t    XAdES-T: a timestamp over the signature value\n"+
				"    --level bes  XAdES-BES",
			request.Level,
		)
	}

	keyPair, err := LoadKeyPair(request.Signer)
	if err != nil {
		return nil, err
	}

	tree, err := parseDocument(request.Content)
	if err != nil {
		return nil, err
	}

	certificateDigest := sha256.Sum256(keyPair.Certificate.Raw)
	signedProperties := buildSignedProperties(
		base64.StdEncoding.EncodeToString(certificateDigest[:]),
		time.Now().UTC().Format(time.RFC3339),
	)
	signedInfo := buildSignedInfo(
		placeholderDigest, placeholderDigest,
		keyPair.Certificate.PublicKeyAlgorithm == x509.ECDSA,
		request.Enveloping,
	)
	payload := ""
	if request.Enveloping {
		payload = `<ds:Object Id="` + payloadObjectID + `">` +
			base64.StdEncoding.EncodeToString(request.Content) + `</ds:Object>`
	}

	signature := buildSignature(signedInfo, placeholderDigest,
		base64.StdEncoding.EncodeToString(keyPair.Certificate.Raw), signedProperties, payload)

	if err := attach(tree, signature, request.Enveloping); err != nil {
		return nil, err
	}

	// Re-parse the serialised skeleton so the tree being measured is byte-for-byte
	// the tree that will be emitted. Measuring the in-memory tree instead gives a
	// different canonical form, because etree's writer and canonicaliser disagree
	// about where namespace declarations land: the digests then match each other
	// but not the file, and every verifier reports a broken signature.
	serialised, err := tree.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialise skeleton: %w", err)
	}
	tree, err = parseDocument(serialised)
	if err != nil {
		return nil, err
	}

	// Pass two: measure what is really on the tree.
	signatureElement := findByID(tree.Root(), signatureID)
	if signatureElement == nil {
		return nil, fmt.Errorf("the assembled signature cannot be located")
	}
	signedInfoElement := signatureElement.SelectElement("SignedInfo")
	if signedInfoElement == nil {
		return nil, fmt.Errorf("SignedInfo is missing from the assembled signature")
	}

	documentDigest, err := digestOfDocument(tree, request.Enveloping)
	if err != nil {
		return nil, err
	}
	propertiesElement := findByID(tree.Root(), signedPropertiesID)
	if propertiesElement == nil {
		return nil, fmt.Errorf("SignedProperties cannot be located")
	}
	propertiesDigest, err := canonicalDigest(propertiesElement)
	if err != nil {
		return nil, err
	}

	references := signedInfoElement.SelectElements("Reference")
	if len(references) != 2 {
		return nil, fmt.Errorf("SignedInfo has %d references, expected 2", len(references))
	}
	setDigestValue(references[0], documentDigest)
	setDigestValue(references[1], propertiesDigest)

	signedInfoDigest, err := canonicalDigest(signedInfoElement)
	if err != nil {
		return nil, err
	}
	signatureValue, err := keyPair.Signer.Sign(rand.Reader, signedInfoDigest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign XAdES SignedInfo: %w", err)
	}

	signatureValueElement := signatureElement.SelectElement("SignatureValue")
	if signatureValueElement == nil {
		return nil, fmt.Errorf("SignatureValue is missing from the assembled signature")
	}
	signatureValueElement.SetText(base64.StdEncoding.EncodeToString(signatureValue))

	// XAdES-T: the token seals the SignatureValue element, not the document. It
	// lives in xades:UnsignedProperties, which is why it can be added after the
	// signature exists at all.
	if request.Level.NeedsTimestamp() {
		if err := s.attachSignatureTimeStamp(ctx, tree, signatureElement, signatureValue, request); err != nil {
			return nil, err
		}
	}

	output := etree.NewDocument()
	output.SetRoot(tree.Root().Copy())

	final, err := output.WriteToBytes()
	if err != nil {
		return nil, err
	}

	// The prolog is prepended at the very end, never inserted into the tree: a
	// processing instruction before the root would change the canonical form and
	// therefore the document digest.
	if !hasXMLDeclaration(final) {
		final = append([]byte(`<?xml version="1.0" encoding="UTF-8"?>`+"\n"), final...)
	}
	return final, nil
}

// placeholderDigest fills the skeleton until the real values are measured.
const placeholderDigest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// digestOfDocument canonicalises the document without its signature.
//
// The enveloped reference signs the whole document, and the signature itself is
// excluded because it did not exist when the reference was created.
func digestOfDocument(tree *etree.Document, enveloping bool) ([]byte, error) {
	root := tree.Root()
	if root == nil {
		return nil, fmt.Errorf("the document has no root")
	}

	if enveloping {
		object := findByID(root, payloadObjectID)
		if object == nil {
			return nil, fmt.Errorf("enveloping signature has no payload Object")
		}
		return canonicalDigest(object)
	}

	stripped := root.Copy()
	for _, child := range stripped.ChildElements() {
		if child.Tag == "Signature" && child.SelectAttrValue("Id", "") == signatureID {
			stripped.RemoveChild(child)
		}
	}
	return canonicalDigest(stripped)
}

// findByID walks the tree looking for an element with the given Id.
func findByID(element *etree.Element, id string) *etree.Element {
	if element == nil {
		return nil
	}
	if element.SelectAttrValue("Id", "") == id {
		return element
	}
	for _, child := range element.ChildElements() {
		if found := findByID(child, id); found != nil {
			return found
		}
	}
	return nil
}

// setDigestValue rewrites the DigestValue of a reference.
func setDigestValue(reference *etree.Element, digest []byte) {
	value := reference.SelectElement("DigestValue")
	if value == nil {
		return
	}
	value.SetText(base64.StdEncoding.EncodeToString(digest))
}

// parseDocument reads the source XML into a tree, keeping its prolog.
func parseDocument(content []byte) (*etree.Document, error) {
	tree := etree.NewDocument()
	if err := tree.ReadFromBytes(content); err != nil {
		return nil, fmt.Errorf("read XML: %w", err)
	}
	if tree.Root() == nil {
		return nil, fmt.Errorf("the document has no root element")
	}
	return tree, nil
}

// parseFragment reads a bare element string.
func parseFragment(fragment string) (*etree.Element, error) {
	wrapper := etree.NewDocument()
	if err := wrapper.ReadFromString("<wrapper>" + fragment + "</wrapper>"); err != nil {
		return nil, fmt.Errorf("parse signature fragment: %w", err)
	}
	root := wrapper.Root()
	if root == nil || len(root.ChildElements()) == 0 {
		return nil, fmt.Errorf("signature fragment is empty")
	}
	return root.ChildElements()[0].Copy(), nil
}

// canonicalDigest applies inclusive c14n and returns the SHA-256 digest.
func canonicalDigest(element *etree.Element) ([]byte, error) {
	canonicalizer := dsig.MakeC14N10RecCanonicalizer()
	canonical, err := canonicalizer.Canonicalize(element)
	if err != nil {
		return nil, fmt.Errorf("canonicalise XML: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return digest[:], nil
}

// buildSignedProperties emits xades:SignedProperties with the namespaces it needs.
func buildSignedProperties(certificateDigest, signingTime string) string {
	return `<xades:SignedProperties xmlns:xades="` + namespaceXades + `" xmlns:ds="` + namespaceDS +
		`" Id="` + signedPropertiesID + `">` +
		`<xades:SignedSignatureProperties>` +
		`<xades:SigningTime>` + signingTime + `</xades:SigningTime>` +
		`<xades:SigningCertificateV2>` +
		`<xades:Cert>` +
		`<xades:CertDigest>` +
		`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
		`<ds:DigestValue>` + certificateDigest + `</ds:DigestValue>` +
		`</xades:CertDigest>` +
		`</xades:Cert>` +
		`</xades:SigningCertificateV2>` +
		`</xades:SignedSignatureProperties>` +
		`</xades:SignedProperties>`
}

// buildSignedInfo emits ds:SignedInfo with the two required references.
func buildSignedInfo(documentDigest, propertiesDigest string, ecdsa, enveloping bool) string {
	method := algorithmRSASHA256
	if ecdsa {
		method = algorithmECDSASHA256
	}

	return `<ds:SignedInfo xmlns:ds="` + namespaceDS + `">` +
		`<ds:CanonicalizationMethod Algorithm="` + algorithmC14N + `"/>` +
		`<ds:SignatureMethod Algorithm="` + method + `"/>` +
		documentReference(enveloping) +
		`<ds:Reference Type="` + typeSignedProperties + `" URI="#` + signedPropertiesID + `">` +
		`<ds:Transforms>` +
		`<ds:Transform Algorithm="` + algorithmC14N + `"/>` +
		`</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
		`<ds:DigestValue>` + propertiesDigest + `</ds:DigestValue>` +
		`</ds:Reference>` +
		`</ds:SignedInfo>`
}

// documentReference builds the reference to the signed payload.
//
// Enveloped signatures reference the whole document with URI="" and must declare
// the enveloped-signature transform, or a verifier hashes the document with the
// signature inside. Enveloping signatures reference their own Object by Id.
func documentReference(enveloping bool) string {
	if enveloping {
		return `<ds:Reference Id="` + documentReferenceID + `" URI="#` + payloadObjectID + `">` +
			`<ds:Transforms>` +
			`<ds:Transform Algorithm="` + algorithmC14N + `"/>` +
			`</ds:Transforms>` +
			`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
			`<ds:DigestValue>` + placeholderDigest + `</ds:DigestValue>` +
			`</ds:Reference>`
	}

	return `<ds:Reference Id="` + documentReferenceID + `" URI="">` +
		`<ds:Transforms>` +
		`<ds:Transform Algorithm="` + algorithmEnveloped + `"/>` +
		`<ds:Transform Algorithm="` + algorithmC14N + `"/>` +
		`</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
		`<ds:DigestValue>` + placeholderDigest + `</ds:DigestValue>` +
		`</ds:Reference>`
}

// buildSignature emits ds:Signature in the order XMLDSig mandates:
// SignedInfo, SignatureValue, KeyInfo, Object.
func buildSignature(signedInfo, signatureValue, certificate, signedProperties, payload string) string {
	return `<ds:Signature xmlns:ds="` + namespaceDS + `" xmlns:xades="` + namespaceXades +
		`" Id="` + signatureID + `">` + signedInfo +
		`<ds:SignatureValue>` + signatureValue + `</ds:SignatureValue>` +
		`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + certificate +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
		payload +
		`<ds:Object><xades:QualifyingProperties Target="#` + signatureID + `">` +
		signedProperties + `</xades:QualifyingProperties></ds:Object>` +
		`</ds:Signature>`
}

// attach inserts the signature into the tree.
//
// Indentation is deliberately left untouched: etree's Indent rewrites text
// nodes, and a single added space inside the root changes the document digest.
func attach(tree *etree.Document, signature string, enveloping bool) error {
	signatureElement, err := parseFragment(signature)
	if err != nil {
		return err
	}

	if enveloping {
		document := etree.NewDocument()
		document.SetRoot(signatureElement)
		tree.SetRoot(document.Root().Copy())
		return nil
	}

	// The source document keeps its own prolog. When it has none, one is added:
	// a signature file without a declaration is still valid XML, but readers that
	// guess the encoding from the first byte mis-handle non-ASCII text.
	tree.Root().AddChild(signatureElement)
	return nil
}

// compile-time checks.
var _ application.XadesSigner = (*XadesSigner)(nil)
var _ = domain.Xades

// hasXMLDeclaration reports whether the bytes already start with a prolog.
func hasXMLDeclaration(content []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(content)), "<?xml")
}

// attachSignatureTimeStamp adds xades:SignatureTimeStamp, turning BES into T.
//
// ETSI EN 319 132-1 says the token covers the canonical form of ds:SignatureValue.
// The token is requested over the digest of the *re-serialised* element, because
// the verifier will canonicalise what is in the file, not what was in memory.
func (s *XadesSigner) attachSignatureTimeStamp(
	ctx context.Context,
	tree *etree.Document,
	signatureElement *etree.Element,
	signatureValue []byte,
	request application.XadesRequest,
) error {
	timestamper := s.timestamps
	if timestamper == nil {
		return fmt.Errorf("XAdES-T needs a timestamp authority: pass --tsa <url>")
	}

	// The element as it will be read: base64 text plus its tags.
	canonical, err := canonicalSignatureValue(tree, signatureElement)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(canonical)
	response, err := timestamper.Token(ctx, digest[:], request.TimestampURL, request.TimestampUser, request.TimestampSecret)
	if err != nil {
		return fmt.Errorf("request the XAdES signature timestamp: %w", err)
	}

	tokenDER, err := cms.ExtractToken(response)
	if err != nil {
		return fmt.Errorf("extract the timestamp token: %w", err)
	}

	// The token travels as a base64 element, exactly as the CMS package emits it.
	unsigned := buildUnsignedProperties(base64.StdEncoding.EncodeToString(tokenDER))

	fragment, err := parseFragment(unsigned)
	if err != nil {
		return fmt.Errorf("build xades:UnsignedProperties: %w", err)
	}

	qualifying := findQualifyingProperties(signatureElement)
	if qualifying == nil {
		return fmt.Errorf("the signature has no xades:QualifyingProperties to extend")
	}
	qualifying.AddChild(fragment)
	return nil
}

// canonicalSignatureValue re-serialises ds:SignatureValue for hashing.
//
// The signature element is copied so the measurement never mutates the tree the
// caller will write: canonicalising in place changes attribute order and
// namespace declarations, which would invalidate the very digest being computed.
func canonicalSignatureValue(tree *etree.Document, signatureElement *etree.Element) ([]byte, error) {
	copyOfSignature := signatureElement.Copy()

	// The copy is detached from its document, so every namespace it inherited
	// must be declared on it; otherwise the canonical form differs from the one
	// a verifier reconstructs from the file.
	ensureNamespace(copyOfSignature, "ds", namespaceDS)
	ensureNamespace(copyOfSignature, "xades", namespaceXades)

	value := copyOfSignature.SelectElement("SignatureValue")
	if value == nil {
		return nil, fmt.Errorf("SignatureValue is missing from the signature")
	}

	// Wrap so the canonicaliser sees the element in a document of its own.
	holder := etree.NewDocument()
	holder.SetRoot(copyOfSignature)
	holder.Indent(0)

	output, err := holder.WriteToBytes()
	if err != nil {
		return nil, err
	}

	// Extract just the element, dropping the prolog the writer adds.
	start := bytes.Index(output, []byte("<ds:Signature"))
	end := bytes.LastIndex(output, []byte("</ds:Signature>"))
	if start < 0 || end < 0 {
		return nil, fmt.Errorf("cannot isolate the serialised signature")
	}
	serialised := output[start : end+len("</ds:Signature>")]

	// The token covers SignatureValue alone, so isolate it again from the
	// serialised signature rather than hashing the whole element.
	valueStart := bytes.Index(serialised, []byte("<ds:SignatureValue>"))
	valueEnd := bytes.Index(serialised, []byte("</ds:SignatureValue>"))
	if valueStart < 0 || valueEnd < 0 {
		return nil, fmt.Errorf("cannot isolate SignatureValue for hashing")
	}
	_ = tree
	return serialised[valueStart : valueEnd+len("</ds:SignatureValue>")], nil
}

// ensureNamespace declares a prefix on an element when it is not already bound.
func ensureNamespace(element *etree.Element, prefix, uri string) {
	attribute := "xmlns:" + prefix
	if element.SelectAttr(attribute) != nil {
		return
	}
	// A prefix already bound to the right URI by an ancestor needs no redeclaration.
	if element.Space == prefix && element.NamespaceURI() == uri {
		return
	}
	element.CreateAttr(attribute, uri)
}

// findQualifyingProperties locates xades:QualifyingProperties in the signature.
func findQualifyingProperties(signature *etree.Element) *etree.Element {
	if signature == nil {
		return nil
	}
	if signature.Tag == "QualifyingProperties" && signature.NamespaceURI() == namespaceXades {
		return signature
	}
	for _, child := range signature.ChildElements() {
		if found := findQualifyingProperties(child); found != nil {
			return found
		}
	}
	return nil
}

// buildUnsignedProperties emits xades:UnsignedProperties with the token.
//
// The Id is required by the schema and referenced by nothing: the token covers
// the signature, not the other way round.
func buildUnsignedProperties(token string) string {
	return `<xades:UnsignedProperties xmlns:xades="` + namespaceXades + `" Id="` + unsignedPropertiesID + `">` +
		`<xades:UnsignedSignatureProperties>` +
		`<xades:SignatureTimeStamp Id="` + signatureTimeStampID + `">` +
		`<ds:CanonicalizationMethod xmlns:ds="` + namespaceDS + `" Algorithm="` + algorithmC14N + `"/>` +
		`<xades:EncapsulatedTimeStamp>` + token + `</xades:EncapsulatedTimeStamp>` +
		`</xades:SignatureTimeStamp>` +
		`</xades:UnsignedSignatureProperties>` +
		`</xades:UnsignedProperties>`
}

// Identifiers used by the timestamp extension.
const (
	unsignedPropertiesID = "firma-it-unsigned-properties"
	signatureTimeStampID = "firma-it-signature-timestamp"
)
