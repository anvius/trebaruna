package infrastructure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// XadesSigner produces XAdES-BES (ETSI EN 319 132-1).
//
// Digests are computed over real c14n output, produced by the xmldsig
// package's canonicaliser on an etree tree. Hashing hand-written strings does
// not work: every verifier re-parses and canonicalises before hashing, so a
// digest taken over the source text never matches.
//
// A third-party XAdES builder was rejected (artemkunich/goxades: 10 stars, no
// commits since 2023). goxmldsig's canonicaliser was used until it was found
// to sort prefixed attributes by local name instead of namespace URI.
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
	algorithmSHA384      = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	algorithmSHA512      = "http://www.w3.org/2001/04/xmlenc#sha512"
	algorithmRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algorithmECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	typeSignedProperties = "http://uri.etsi.org/01903#SignedProperties"

	// encodingBase64 names the transfer encoding of an enveloped payload.
	encodingBase64 = "http://www.w3.org/2000/09/xmldsig#base64"
)

// signatureIDs name the elements of one signature. Each signature gets a
// suffix of its own: a document can carry several, and a reference to an Id
// must find exactly one element.
type signatureIDs struct{ suffix string }

func newSignatureIDs() (signatureIDs, error) {
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return signatureIDs{}, fmt.Errorf("signature identifiers: %w", err)
	}
	return signatureIDs{suffix: hex.EncodeToString(random)}, nil
}

func (ids signatureIDs) signature() string        { return "trebaruna-signature-" + ids.suffix }
func (ids signatureIDs) signedProperties() string { return "trebaruna-signed-properties-" + ids.suffix }
func (ids signatureIDs) reference() string        { return "trebaruna-reference-" + ids.suffix }

// value names the SignatureValue, from the start: a counter-signature
// names it by that Id, and one given later would change the value's
// canonical form under the timestamps that seal it.
func (ids signatureIDs) value() string { return "trebaruna-signature-value-" + ids.suffix }

// referenceAt names the reference to the index-th document of a detached
// signature that signs several.
func (ids signatureIDs) referenceAt(index int) string {
	if index == 0 {
		return ids.reference()
	}
	return ids.reference() + "-" + strconv.Itoa(index+1)
}
func (ids signatureIDs) payload() string { return "trebaruna-payload-" + ids.suffix }

// manifest is the ds:Manifest holding the references to documents named
// by address.
func (ids signatureIDs) manifest() string { return "trebaruna-manifest-" + ids.suffix }

// AutoFirma's names for the root and the content of an internally detached
// signature.
func (ids signatureIDs) afirmaRoot() string { return "AFIRMA-Root-" + ids.suffix }
func (ids signatureIDs) content() string    { return "CONTENT-" + ids.suffix }

// idBeside names a property added to a signature after it is made (its
// timestamps), from the signature's own Id.
func idBeside(signature *etree.Element, name string) string {
	return signature.SelectAttrValue("Id", "trebaruna-signature") + "-" + name
}

// SignXades signs the document in place (enveloped), inside the signature
// (enveloping), beside it (detached) or in AutoFirma's AFIRMA layout
// (internally detached); documentLayout holds what differs.
//
// Two passes, because the digests must cover the tree exactly as it will be
// read back. Pass one inserts a skeleton with placeholder values; pass two
// canonicalises the real nodes in their final position, fills the digests, and
// signs SignedInfo. Formatting is never touched: re-indenting an element
// changes its text nodes and therefore its digest.
func (s *XadesSigner) SignXades(ctx context.Context, request application.XadesRequest) ([]byte, error) {
	if err := levelReady(request); err != nil {
		return nil, err
	}

	keyPair, err := LoadKeyPair(request.Signer)
	if err != nil {
		return nil, err
	}
	defer keyPair.Close()

	if request.Countersign != "" {
		return s.countersignXades(ctx, request, keyPair)
	}
	if request.Plain && (request.Level != domain.BES || !request.Policy.IsZero() || len(request.ClaimedRoles) > 0) {
		return nil, fmt.Errorf("XMLDSig signatures carry no signed properties: no timestamp, policy or role; use XAdES")
	}
	layout, err := layoutFor(request)
	if err != nil {
		return nil, err
	}
	ids, err := newSignatureIDs()
	if err != nil {
		return nil, err
	}
	tree := layout.tree(ids, request.Content)

	signedProperties := ""
	if !layout.plain {
		certificateDigest := sha256.Sum256(keyPair.Certificate.Raw)
		signedProperties = buildSignedProperties(ids,
			base64.StdEncoding.EncodeToString(certificateDigest[:]),
			time.Now().UTC().Format(time.RFC3339),
			layout.dataObjectFormats(ids),
			policyProperties(request.Policy)+placeProperties(request.Place)+roleProperties(request.ClaimedRoles),
		)
	}
	signedInfo := buildSignedInfo(ids,
		placeholderDigest, placeholderDigest,
		keyPair.Certificate.PublicKeyAlgorithm == x509.ECDSA,
		layout,
	)
	payload, err := layout.payload(ids, request.Content)
	if err != nil {
		return nil, err
	}

	signature := buildSignature(ids, signedInfo, placeholderDigest,
		base64.StdEncoding.EncodeToString(keyPair.Certificate.Raw), signedProperties, payload, layout.holder != nil)

	if err := attach(tree, signature); err != nil {
		return nil, err
	}
	resolve := layout.resolver()

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
	signatureElement := findByID(tree.Root(), ids.signature())
	if signatureElement == nil {
		return nil, fmt.Errorf("the assembled signature cannot be located")
	}
	signedInfoElement := signatureElement.SelectElement("SignedInfo")
	if signedInfoElement == nil {
		return nil, fmt.Errorf("SignedInfo is missing from the assembled signature")
	}

	// Each reference is digested the way a verifier dereferences it, with the
	// same code trebaruna's verifier runs: the document node for URI="" (the
	// instructions outside the root included), the Object or SignedProperties
	// for an Id.
	references := signedInfoElement.SelectElements("Reference")
	if expected := layout.referenceCount(); len(references) != expected {
		return nil, fmt.Errorf("SignedInfo has %d references, expected %d", len(references), expected)
	}
	for _, reference := range references {
		if layout.presetDigest(reference.SelectAttrValue("URI", "")) {
			continue
		}
		data, err := xmldsig.ReferenceData(tree, signatureElement, reference, resolve)
		if err != nil {
			return nil, fmt.Errorf("digest %s: %w", reference.SelectAttrValue("URI", ""), err)
		}
		digest := sha256.Sum256(data)
		setDigestValue(reference, digest[:])
	}

	signedInfoDigest, err := canonicalDigest(signedInfoElement)
	if err != nil {
		return nil, err
	}
	signatureValue, err := keyPair.Signer.Sign(rand.Reader, signedInfoDigest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign XAdES SignedInfo: %w", err)
	}
	if signatureValue, err = xmldsigValue(keyPair.Certificate.PublicKey, signatureValue); err != nil {
		return nil, err
	}

	signatureValueElement := signatureElement.SelectElement("SignatureValue")
	if signatureValueElement == nil {
		return nil, fmt.Errorf("SignatureValue is missing from the assembled signature")
	}
	signatureValueElement.SetText(base64.StdEncoding.EncodeToString(signatureValue))

	if err := s.extend(ctx, tree, signatureElement, request, keyPair, resolve); err != nil {
		return nil, err
	}

	// The whole tree is written: the processing instructions and comments
	// outside the root (a FatturaPA's stylesheet) belong to the document.
	final, err := tree.WriteToBytes()
	if err != nil {
		return nil, err
	}

	// A document without an XML declaration gets one at the very end. The
	// declaration is part of no canonical form, so the digests stay valid.
	if !hasXMLDeclaration(final) {
		final = append([]byte(`<?xml version="1.0" encoding="UTF-8"?>`+"\n"), final...)
	}
	return final, nil
}

// levelReady refuses, before any key is used, a level the request cannot
// reach: XAdES-T and above need a token over the signature value, which only
// exists after the signature is computed, and accepting LTA while emitting
// B-T would report a level the file does not have.
func levelReady(request application.XadesRequest) error {
	if (request.Level.NeedsTimestamp() || request.Level.Archival()) && request.TimestampURL == "" {
		return fmt.Errorf("%s for XAdES needs a timestamp authority: pass --tsa <url>", request.Level)
	}
	return nil
}

// extend adds the unsigned properties the level asks for, in the order XAdES
// layers them over a signature already computed.
func (s *XadesSigner) extend(ctx context.Context, tree *etree.Document, signatureElement *etree.Element,
	request application.XadesRequest, keyPair KeyPair, resolve xmldsig.Resolver) error {
	// XAdES-T: the token seals the SignatureValue element, not the document. It
	// lives in xades:UnsignedProperties, which is why it can be added after the
	// signature exists at all.
	if request.Level.NeedsTimestamp() {
		if err := s.attachSignatureTimeStamp(ctx, signatureElement, request); err != nil {
			return err
		}
	}

	// XAdES-LT: the revocation material goes into UnsignedSignatureProperties
	// before the archive timestamp, because the archive timestamp must cover it.
	if request.Level.EmbedsRevocation() {
		if !request.EmbedRevocation {
			return fmt.Errorf(
				"%s for XAdES needs embedded revocation and a source for it:\n"+
					"    --level %s --online-revocation   query OCSP and attach the answers",
				request.Level, request.Level)
		}
		if err := s.attachRevocationValues(ctx, signatureElement, keyPair); err != nil {
			return err
		}
	}

	// XAdES-A: the archive timestamp covers every object of the signature,
	// including the unsigned properties just written. It is the outermost layer,
	// so nothing may be added to the signature afterwards.
	if request.Level.Archival() {
		return s.attachArchiveTimeStamp(ctx, tree, signatureElement, request, resolve)
	}
	return nil
}

// placeholderDigest fills the skeleton until the real values are measured.
const placeholderDigest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

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
	canonical, err := xmldsig.Canonicalize(element, xmldsig.C14N10, "")
	if err != nil {
		return nil, fmt.Errorf("canonicalise XML: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return digest[:], nil
}

// xmldsigValue is the signature value XML-DSig writes for the key: an ECDSA
// signature rewritten from the ASN.1 SEQUENCE a signer returns into the
// fixed-width r||s XML-DSig requires (RFC 6931 §2.3.6), on a NIST or a
// Brainpool curve; any other signature as it is. The ASN.1 form verified
// with our own reader and failed with every other one.
func xmldsigValue(public crypto.PublicKey, der []byte) ([]byte, error) {
	var size int
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		size = (key.Curve.Params().BitSize + 7) / 8
	case *brainpool.PublicKey:
		size = (key.Curve.N.BitLen() + 7) / 8
	default:
		return der, nil
	}
	var parts struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &parts); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("unreadable ECDSA signature: %v", err)
	}
	raw := make([]byte, 2*size)
	parts.R.FillBytes(raw[:size])
	parts.S.FillBytes(raw[size:])
	return raw, nil
}

// buildSignedProperties emits xades:SignedProperties with the namespaces it needs.
//
// DataObjectFormat states the media type of what was signed, bound to the
// document reference: the XAdES baseline profile (ETSI EN 319 132-1, B-B)
// requires it, and validators such as the EU DSS check for it. formats are
// the DataObjectFormat elements the layout writes, one per signed document.
func buildSignedProperties(ids signatureIDs, certificateDigest, signingTime, formats, declarations string) string {
	return `<xades:SignedProperties xmlns:xades="` + namespaceXades + `" xmlns:ds="` + namespaceDS +
		`" Id="` + ids.signedProperties() + `">` +
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
		declarations +
		`</xades:SignedSignatureProperties>` +
		`<xades:SignedDataObjectProperties>` + formats +
		`</xades:SignedDataObjectProperties>` +
		`</xades:SignedProperties>`
}

// xmlDigestAlgorithms are the XMLDSig URIs of the policy digests.
var xmlDigestAlgorithms = map[string]string{
	"SHA1":   "http://www.w3.org/2000/09/xmldsig#sha1",
	"SHA256": algorithmSHA256,
	"SHA384": "http://www.w3.org/2001/04/xmldsig-more#sha384",
	"SHA512": "http://www.w3.org/2001/04/xmlenc#sha512",
}

// policyProperties writes SignaturePolicyIdentifier (EN 319 132-1, 5.2.9):
// an OID as "urn:oid:" qualified OIDAsURN, as AutoFirma writes it; a URL as it
// is (FacturaE's).
func policyProperties(policy domain.SignaturePolicy) string {
	if policy.IsZero() {
		return ""
	}
	identifier := `<xades:Identifier>` + xmlEscape(policy.Identifier()) + `</xades:Identifier>`
	if _, isOID := policy.OID(); isOID {
		identifier = `<xades:Identifier Qualifier="OIDAsURN">urn:oid:` + policy.Identifier() + `</xades:Identifier>`
	}
	qualifiers := ""
	if policy.Qualifier() != "" {
		qualifiers = `<xades:SigPolicyQualifiers><xades:SigPolicyQualifier><xades:SPURI>` + xmlEscape(policy.Qualifier()) +
			`</xades:SPURI></xades:SigPolicyQualifier></xades:SigPolicyQualifiers>`
	}
	return `<xades:SignaturePolicyIdentifier><xades:SignaturePolicyId>` +
		`<xades:SigPolicyId>` + identifier + `</xades:SigPolicyId>` +
		`<xades:SigPolicyHash><ds:DigestMethod Algorithm="` + xmlDigestAlgorithms[policy.HashAlgorithm()] + `"/>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(policy.Hash()) + `</ds:DigestValue></xades:SigPolicyHash>` +
		qualifiers + `</xades:SignaturePolicyId></xades:SignaturePolicyIdentifier>`
}

// placeProperties declares where the signature was made
// (SignatureProductionPlaceV2, EN 319 132-1 5.2.5), between the policy and
// the roles as the schema orders them.
func placeProperties(place domain.ProductionPlace) string {
	if place.IsZero() {
		return ""
	}
	var parts string
	for _, part := range []struct{ name, value string }{
		{"City", place.City}, {"StateOrProvince", place.Province}, {"PostalCode", place.PostalCode}, {"CountryName", place.Country},
	} {
		if part.value != "" {
			parts += `<xades:` + part.name + `>` + xmlEscape(part.value) + `</xades:` + part.name + `>`
		}
	}
	return `<xades:SignatureProductionPlaceV2>` + parts + `</xades:SignatureProductionPlaceV2>`
}

// roleProperties writes the roles the signer claims (SignerRoleV2).
func roleProperties(roles []string) string {
	if len(roles) == 0 {
		return ""
	}
	claimed := ""
	for _, role := range roles {
		claimed += `<xades:ClaimedRole>` + xmlEscape(role) + `</xades:ClaimedRole>`
	}
	return `<xades:SignerRoleV2><xades:ClaimedRoles>` + claimed + `</xades:ClaimedRoles></xades:SignerRoleV2>`
}

// xmlEscape escapes text for an element's content.
func xmlEscape(text string) string {
	var builder strings.Builder
	_ = xml.EscapeText(&builder, []byte(text))
	return builder.String()
}

// buildSignedInfo emits ds:SignedInfo with the two required references.
func buildSignedInfo(ids signatureIDs, documentDigest, propertiesDigest string, ecdsa bool, layout documentLayout) string {
	method := algorithmRSASHA256
	if ecdsa {
		method = algorithmECDSASHA256
	}

	properties := ""
	if !layout.plain {
		properties = `<ds:Reference Type="` + typeSignedProperties + `" URI="#` + ids.signedProperties() + `">` +
			`<ds:Transforms>` +
			`<ds:Transform Algorithm="` + algorithmC14N + `"/>` +
			`</ds:Transforms>` +
			`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
			`<ds:DigestValue>` + propertiesDigest + `</ds:DigestValue>` +
			`</ds:Reference>`
	}
	return `<ds:SignedInfo xmlns:ds="` + namespaceDS + `">` +
		`<ds:CanonicalizationMethod Algorithm="` + algorithmC14N + `"/>` +
		`<ds:SignatureMethod Algorithm="` + method + `"/>` +
		layout.documentReference(ids) + properties +
		`</ds:SignedInfo>`
}

// buildSignature emits ds:Signature in the order XMLDSig mandates:
// SignedInfo, SignatureValue, KeyInfo, Object.
//
// A plain XMLDSig signature (no signed properties) has no QualifyingProperties.
//
// ownDefault redeclares the default namespace as XML-Signature's, for a
// signature placed in a document that has a default of its own (ODF's
// document-signatures): otherwise SignedInfo's canonical form carries the
// holder's default, and a reader that rebuilds the signature alone, as
// LibreOffice does, computes another one.
func buildSignature(ids signatureIDs, signedInfo, signatureValue, certificate, signedProperties, payload string, ownDefault bool) string {
	namespaces, qualifying := `xmlns:ds="`+namespaceDS+`"`, ""
	if ownDefault {
		namespaces = `xmlns="` + namespaceDS + `" ` + namespaces
	}
	if signedProperties != "" {
		namespaces += ` xmlns:xades="` + namespaceXades + `"`
		qualifying = `<ds:Object><xades:QualifyingProperties Target="#` + ids.signature() + `">` +
			signedProperties + `</xades:QualifyingProperties></ds:Object>`
	}
	return `<ds:Signature ` + namespaces + ` Id="` + ids.signature() + `">` + signedInfo +
		`<ds:SignatureValue Id="` + ids.value() + `">` + signatureValue + `</ds:SignatureValue>` +
		`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + certificate +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
		payload + qualifying +
		`</ds:Signature>`
}

// attach puts the signature at the end of the document's root, or makes it
// the root of an empty document (enveloping, detached).
//
// Indentation is deliberately left untouched: etree's Indent rewrites text
// nodes, and a single added space inside the root changes the document digest.
func attach(tree *etree.Document, signature string) error {
	signatureElement, err := parseFragment(signature)
	if err != nil {
		return err
	}
	if tree.Root() == nil {
		tree.SetRoot(signatureElement)
		return nil
	}
	tree.Root().AddChild(signatureElement)
	return nil
}

// compile-time checks.
var _ application.XadesSigner = (*XadesSigner)(nil)
var _ = domain.Xades

// xmlDeclaration matches the XML declaration, not a processing instruction
// whose name starts with xml, such as xml-stylesheet.
var xmlDeclaration = regexp.MustCompile(`^<\?xml\s`)

// hasXMLDeclaration reports whether the bytes already start with a prolog.
func hasXMLDeclaration(content []byte) bool {
	return xmlDeclaration.Match(bytes.TrimSpace(content))
}

// attachSignatureTimeStamp adds xades:SignatureTimeStamp, turning BES into T.
//
// ETSI EN 319 132-1 says the token covers the canonical form of ds:SignatureValue.
// The token is requested over the digest of the *re-serialised* element, because
// the verifier will canonicalise what is in the file, not what was in memory.
func (s *XadesSigner) attachSignatureTimeStamp(
	ctx context.Context,
	signatureElement *etree.Element,
	request application.XadesRequest,
) error {
	timestamper := s.timestamps
	if timestamper == nil {
		return fmt.Errorf("XAdES-T needs a timestamp authority: pass --tsa <url>")
	}

	// The canonical SignatureValue, as every validator recomputes it.
	canonical, err := canonicalSignatureValue(signatureElement)
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
	unsigned := buildUnsignedProperties(signatureElement, base64.StdEncoding.EncodeToString(tokenDER))

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

// canonicalSignatureValue is what a SignatureTimeStamp covers: the canonical
// form of ds:SignatureValue where it stands (EN 319 132-1, 5.4.1.3), with
// the C14N the timestamp declares. In place, the namespaces it inherits
// (the signature's, and the document's around it) are part of that form.
func canonicalSignatureValue(signatureElement *etree.Element) ([]byte, error) {
	value := signatureElement.SelectElement("SignatureValue")
	if value == nil {
		return nil, fmt.Errorf("SignatureValue is missing from the signature")
	}
	return xmldsig.Canonicalize(value, xmldsig.C14N10, "")
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
func buildUnsignedProperties(signature *etree.Element, token string) string {
	return `<xades:UnsignedProperties xmlns:xades="` + namespaceXades + `" Id="` + idBeside(signature, "unsigned-properties") + `">` +
		`<xades:UnsignedSignatureProperties>` +
		`<xades:SignatureTimeStamp Id="` + idBeside(signature, "timestamp") + `">` +
		`<ds:CanonicalizationMethod xmlns:ds="` + namespaceDS + `" Algorithm="` + algorithmC14N + `"/>` +
		`<xades:EncapsulatedTimeStamp>` + token + `</xades:EncapsulatedTimeStamp>` +
		`</xades:SignatureTimeStamp>` +
		`</xades:UnsignedSignatureProperties>` +
		`</xades:UnsignedProperties>`
}

// archiveNamespace is the XAdES 1.4.1 namespace that defines ArchiveTimeStamp.
const archiveNamespace = "http://uri.etsi.org/01903/v1.4.1#"

// attachArchiveTimeStamp adds xades141:ArchiveTimeStamp, making the signature
// XAdES-A (ETSI EN 319 132-1 §5.5.2).
//
// The token does not cover the document. It covers every object the signature
// already has: each ds:Reference target, then ds:SignedInfo, ds:SignatureValue,
// ds:KeyInfo, then each unsigned qualifying property in order, and finally the
// other ds:Object elements. That is what makes the archival level survive the
// expiry of the certificates it protects: the proof of their state at signing
// time is inside the sealed bytes.
func (s *XadesSigner) attachArchiveTimeStamp(
	ctx context.Context,
	tree *etree.Document,
	signatureElement *etree.Element,
	request application.XadesRequest,
	resolve xmldsig.Resolver,
) error {
	timestamper := s.timestamps
	if timestamper == nil {
		return fmt.Errorf("XAdES-A needs a timestamp authority: pass --tsa <url>")
	}

	covered, err := xmldsig.ArchiveTimeStampInput(tree, signatureElement, resolve, xmldsig.C14N10, nil)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(covered)
	response, err := timestamper.Token(ctx, digest[:], request.TimestampURL, request.TimestampUser, request.TimestampSecret)
	if err != nil {
		return fmt.Errorf("request the XAdES archive timestamp: %w", err)
	}

	tokenDER, err := cms.ExtractToken(response)
	if err != nil {
		return fmt.Errorf("extract the archive timestamp token: %w", err)
	}

	unsigned := findUnsignedSignatureProperties(signatureElement)
	if unsigned == nil {
		return fmt.Errorf("the signature has no xades:UnsignedSignatureProperties to extend")
	}

	fragment, err := parseFragment(buildArchiveTimeStamp(signatureElement, base64.StdEncoding.EncodeToString(tokenDER)))
	if err != nil {
		return fmt.Errorf("build xades141:ArchiveTimeStamp: %w", err)
	}
	unsigned.AddChild(fragment)
	return nil
}

// walkElement visits an element and its descendants.
func walkElement(element *etree.Element, visit func(*etree.Element)) {
	if element == nil {
		return
	}
	visit(element)
	for _, child := range element.ChildElements() {
		walkElement(child, visit)
	}
}

// findUnsignedSignatureProperties locates the container for unsigned properties.
func findUnsignedSignatureProperties(signature *etree.Element) *etree.Element {
	var found *etree.Element
	walkElement(signature, func(element *etree.Element) {
		if found == nil && element.Tag == "UnsignedSignatureProperties" {
			found = element
		}
	})
	return found
}

// buildArchiveTimeStamp emits the qualifying property in the 1.4.1 namespace.
func buildArchiveTimeStamp(signature *etree.Element, token string) string {
	return `<xades141:ArchiveTimeStamp xmlns:xades141="` + archiveNamespace + `" Id="` + idBeside(signature, "archive-timestamp") + `">` +
		`<ds:CanonicalizationMethod xmlns:ds="` + namespaceDS + `" Algorithm="` + algorithmC14N + `"/>` +
		`<xades:EncapsulatedTimeStamp xmlns:xades="` + namespaceXades + `">` + token + `</xades:EncapsulatedTimeStamp>` +
		`</xades141:ArchiveTimeStamp>`
}

// attachRevocationValues adds the validation material XAdES-LT carries
// (ETSI EN 319 132-1, 5.5.1 and 5.5.2): xades:CertificateValues with the
// certificates ds:KeyInfo leaves out, the signer's issuers and the chain of
// the authority behind the signature timestamp, and xades:RevocationValues
// with an OCSP answer for each of them. Without the issuers a validator
// that is not given them cannot build the chain (EU DSS reported "no
// certificate chain found"); without the authority's material it rates the
// signature at T.
//
// Both live in UnsignedSignatureProperties, so they are not covered by the
// signature value — which is exactly why XAdES-LTA then covers them with an
// archive timestamp.
func (s *XadesSigner) attachRevocationValues(
	ctx context.Context,
	signature *etree.Element,
	keyPair KeyPair,
) error {
	var tokens [][]byte
	for _, stamp := range signature.FindElements(".//SignatureTimeStamp/EncapsulatedTimeStamp") {
		if token, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(stamp.Text()), "")); err == nil {
			tokens = append(tokens, token)
		}
	}
	material, err := gatherValidationMaterial(ctx, keyPair, tokens, "XAdES-LT cannot carry a complete RevocationValues element")
	if err != nil {
		return err
	}

	unsigned := findUnsignedSignatureProperties(signature)
	if unsigned == nil {
		return fmt.Errorf("the signature has no xades:UnsignedSignatureProperties to extend")
	}
	if beyondKeyInfo := material.certificates()[1:]; len(beyondKeyInfo) > 0 {
		fragment, err := parseFragment(buildCertificateValues(beyondKeyInfo))
		if err != nil {
			return fmt.Errorf("build xades:CertificateValues: %w", err)
		}
		unsigned.AddChild(fragment)
	}
	fragment, err := parseFragment(buildRevocationValues(material.responses))
	if err != nil {
		return fmt.Errorf("build xades:RevocationValues: %w", err)
	}
	unsigned.AddChild(fragment)
	return nil
}

// buildCertificateValues emits the xades:CertificateValues element, each
// certificate base64-encoded in an xades:EncapsulatedX509Certificate.
func buildCertificateValues(certificates []*x509.Certificate) string {
	var builder strings.Builder
	builder.WriteString(`<xades:CertificateValues xmlns:xades="` + namespaceXades + `">`)
	for _, certificate := range certificates {
		builder.WriteString(`<xades:EncapsulatedX509Certificate>`)
		builder.WriteString(base64.StdEncoding.EncodeToString(certificate.Raw))
		builder.WriteString(`</xades:EncapsulatedX509Certificate>`)
	}
	builder.WriteString(`</xades:CertificateValues>`)
	return builder.String()
}

// buildRevocationValues emits the xades:RevocationValues element.
//
// The OCSP responses travel base64-encoded inside xades:EncapsulatedOCSPValue, in
// the namespace the schema requires, and in the order the responder produced them.
func buildRevocationValues(ocspResponses [][]byte) string {
	var builder strings.Builder
	builder.WriteString(`<xades:RevocationValues xmlns:xades="` + namespaceXades + `">`)
	builder.WriteString(`<xades:OCSPValues>`)
	for _, response := range ocspResponses {
		builder.WriteString(`<xades:EncapsulatedOCSPValue>`)
		builder.WriteString(base64.StdEncoding.EncodeToString(response))
		builder.WriteString(`</xades:EncapsulatedOCSPValue>`)
	}
	builder.WriteString(`</xades:OCSPValues>`)
	builder.WriteString(`</xades:RevocationValues>`)
	return builder.String()
}
