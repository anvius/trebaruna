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
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
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
func (ids signatureIDs) payload() string          { return "trebaruna-payload-" + ids.suffix }

// idBeside names a property added to a signature after it is made (its
// timestamps), from the signature's own Id.
func idBeside(signature *etree.Element, name string) string {
	return signature.SelectAttrValue("Id", "trebaruna-signature") + "-" + name
}

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
	// The archive timestamp covers a different input from the signature one and
	// is built by its own function below.
	if request.Level.Archival() && request.TimestampURL == "" {
		return nil, fmt.Errorf(
			"%s for XAdES needs a timestamp authority: pass --tsa <url>", request.Level)
	}

	keyPair, err := LoadKeyPair(request.Signer)
	if err != nil {
		return nil, err
	}
	defer keyPair.Close()

	tree, err := parseDocument(request.Content)
	if err != nil {
		return nil, err
	}

	ids, err := newSignatureIDs()
	if err != nil {
		return nil, err
	}
	certificateDigest := sha256.Sum256(keyPair.Certificate.Raw)
	signedProperties := buildSignedProperties(ids,
		base64.StdEncoding.EncodeToString(certificateDigest[:]),
		time.Now().UTC().Format(time.RFC3339),
		request.Enveloping,
		policyProperties(request.Policy)+roleProperties(request.ClaimedRoles),
	)
	signedInfo := buildSignedInfo(ids,
		placeholderDigest, placeholderDigest,
		keyPair.Certificate.PublicKeyAlgorithm == x509.ECDSA,
		documentLayout{enveloping: request.Enveloping, excludeSignatures: !request.Policy.IsFacturaE()},
	)
	payload := ""
	if request.Enveloping {
		payload = `<ds:Object Id="` + ids.payload() + `">` +
			base64.StdEncoding.EncodeToString(request.Content) + `</ds:Object>`
	}

	signature := buildSignature(ids, signedInfo, placeholderDigest,
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
	if len(references) != 2 {
		return nil, fmt.Errorf("SignedInfo has %d references, expected 2", len(references))
	}
	for _, reference := range references {
		data, err := xmldsig.ReferenceData(tree, signatureElement, reference, nil)
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
	if key, ok := keyPair.Certificate.PublicKey.(*ecdsa.PublicKey); ok {
		if signatureValue, err = xmldsigECDSA(key, signatureValue); err != nil {
			return nil, err
		}
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

	// XAdES-LT: the revocation material goes into UnsignedSignatureProperties
	// before the archive timestamp, because the archive timestamp must cover it.
	if request.Level.EmbedsRevocation() {
		if !request.EmbedRevocation {
			return nil, fmt.Errorf(
				"%s for XAdES needs embedded revocation and a source for it:\n"+
					"    --level %s --online-revocation   query OCSP and attach the answers",
				request.Level, request.Level)
		}
		if err := s.attachRevocationValues(ctx, signatureElement, keyPair); err != nil {
			return nil, err
		}
	}

	// XAdES-A: the archive timestamp covers every object of the signature,
	// including the unsigned properties just written. It is the outermost layer,
	// so nothing may be added to the signature afterwards.
	if request.Level.Archival() {
		if err := s.attachArchiveTimeStamp(ctx, tree, signatureElement, request); err != nil {
			return nil, err
		}
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
	canonicalizer := dsig.MakeC14N10RecCanonicalizer()
	canonical, err := canonicalizer.Canonicalize(element)
	if err != nil {
		return nil, fmt.Errorf("canonicalise XML: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return digest[:], nil
}

// xmldsigECDSA rewrites an ECDSA signature from the ASN.1 SEQUENCE Go returns
// into the fixed-width r||s that XML-DSig requires (RFC 6931 §2.3.6). The ASN.1
// form verified with our own reader and failed with every other one.
func xmldsigECDSA(key *ecdsa.PublicKey, der []byte) ([]byte, error) {
	var parts struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &parts); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("unreadable ECDSA signature: %v", err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	raw := make([]byte, 2*size)
	parts.R.FillBytes(raw[:size])
	parts.S.FillBytes(raw[size:])
	return raw, nil
}

// buildSignedProperties emits xades:SignedProperties with the namespaces it needs.
//
// DataObjectFormat states the media type of what was signed, bound to the
// document reference: the XAdES baseline profile (ETSI EN 319 132-1, B-B)
// requires it, and validators such as the EU DSS check for it. An enveloped
// signature signs the XML it sits in; an enveloping one carries the file as
// base64 inside its own Object.
func buildSignedProperties(ids signatureIDs, certificateDigest, signingTime string, enveloping bool, declarations string) string {
	format := `<xades:MimeType>text/xml</xades:MimeType>`
	if enveloping {
		format = `<xades:MimeType>application/octet-stream</xades:MimeType>` +
			`<xades:Encoding>` + encodingBase64 + `</xades:Encoding>`
	}
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
		`<xades:SignedDataObjectProperties>` +
		`<xades:DataObjectFormat ObjectReference="#` + ids.reference() + `">` + format +
		`</xades:DataObjectFormat>` +
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

	return `<ds:SignedInfo xmlns:ds="` + namespaceDS + `">` +
		`<ds:CanonicalizationMethod Algorithm="` + algorithmC14N + `"/>` +
		`<ds:SignatureMethod Algorithm="` + method + `"/>` +
		documentReference(ids, layout) +
		`<ds:Reference Type="` + typeSignedProperties + `" URI="#` + ids.signedProperties() + `">` +
		`<ds:Transforms>` +
		`<ds:Transform Algorithm="` + algorithmC14N + `"/>` +
		`</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
		`<ds:DigestValue>` + propertiesDigest + `</ds:DigestValue>` +
		`</ds:Reference>` +
		`</ds:SignedInfo>`
}

// documentLayout says how a signature holds what it signs.
type documentLayout struct {
	// enveloping carries the document inside the signature, in an Object.
	enveloping bool
	// excludeSignatures leaves every signature out of an enveloped reference
	// (AutoFirma's XPath filter), so a signature added later to the document
	// does not break this one. FacturaE invoices take one signature and
	// AutoFirma writes none.
	excludeSignatures bool
}

// documentReference builds the reference to the signed payload.
//
// Enveloped signatures reference the whole document with URI="" and must declare
// the enveloped-signature transform, or a verifier hashes the document with the
// signature inside. Enveloping signatures reference their own Object by Id.
func documentReference(ids signatureIDs, layout documentLayout) string {
	if layout.enveloping {
		return `<ds:Reference Id="` + ids.reference() + `" URI="#` + ids.payload() + `">` +
			`<ds:Transforms>` +
			`<ds:Transform Algorithm="` + algorithmC14N + `"/>` +
			`</ds:Transforms>` +
			`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
			`<ds:DigestValue>` + placeholderDigest + `</ds:DigestValue>` +
			`</ds:Reference>`
	}

	filter := ""
	if layout.excludeSignatures {
		filter = `<ds:Transform Algorithm="` + xmldsig.XPathTransform + `">` +
			`<ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform>`
	}
	return `<ds:Reference Id="` + ids.reference() + `" URI="">` +
		`<ds:Transforms>` +
		`<ds:Transform Algorithm="` + algorithmEnveloped + `"/>` +
		filter +
		`<ds:Transform Algorithm="` + algorithmC14N + `"/>` +
		`</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
		`<ds:DigestValue>` + placeholderDigest + `</ds:DigestValue>` +
		`</ds:Reference>`
}

// buildSignature emits ds:Signature in the order XMLDSig mandates:
// SignedInfo, SignatureValue, KeyInfo, Object.
func buildSignature(ids signatureIDs, signedInfo, signatureValue, certificate, signedProperties, payload string) string {
	return `<ds:Signature xmlns:ds="` + namespaceDS + `" xmlns:xades="` + namespaceXades +
		`" Id="` + ids.signature() + `">` + signedInfo +
		`<ds:SignatureValue>` + signatureValue + `</ds:SignatureValue>` +
		`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + certificate +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
		payload +
		`<ds:Object><xades:QualifyingProperties Target="#` + ids.signature() + `">` +
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
) error {
	timestamper := s.timestamps
	if timestamper == nil {
		return fmt.Errorf("XAdES-A needs a timestamp authority: pass --tsa <url>")
	}

	covered, err := archiveTimestampInput(tree, signatureElement)
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

// archiveTimestampInput builds the octet stream the archive token must cover.
//
// Steps follow §5.5.2.2 literally: the reference targets in document order, the
// three core signature elements, the unsigned qualifying properties, and the
// remaining ds:Object elements excluding the one that holds the signature
// properties. Anything added later changes this stream and breaks the token,
// which is the guarantee the level provides.
func archiveTimestampInput(tree *etree.Document, signature *etree.Element) ([]byte, error) {
	var input bytes.Buffer

	// 1-3: every ds:Reference of SignedInfo, processed as XML-Signature
	// processes it: the document (URI="", every signature left out) and the
	// SignedProperties, by the same code that computed their digests.
	signedInfo := signature.SelectElement("SignedInfo")
	if signedInfo == nil {
		return nil, fmt.Errorf("the signature has no SignedInfo")
	}
	for _, reference := range signedInfo.SelectElements("Reference") {
		processed, err := xmldsig.ReferenceData(tree, signature, reference, nil)
		if err != nil {
			return nil, fmt.Errorf("archive timestamp: reference %q: %w", reference.SelectAttrValue("URI", ""), err)
		}
		input.Write(processed)
	}

	// 4: SignedInfo, SignatureValue and KeyInfo, in that order.
	for _, name := range []string{"SignedInfo", "SignatureValue", "KeyInfo"} {
		element := signature.SelectElement(name)
		if element == nil {
			continue
		}
		canonical, err := canonicalise(element)
		if err != nil {
			return nil, err
		}
		input.Write(canonical)
	}

	// 5: the unsigned qualifying properties, in document order. This includes
	// the SignatureTimeStamp written a moment ago, which is why A implies T.
	if unsigned := findUnsignedSignatureProperties(signature); unsigned != nil {
		for _, property := range unsigned.ChildElements() {
			canonical, err := canonicalise(property)
			if err != nil {
				return nil, err
			}
			input.Write(canonical)
		}
	}

	// 6: the ds:Object elements that do not hold QualifyingProperties.
	for _, object := range signature.SelectElements("Object") {
		if containsQualifyingProperties(object) {
			continue
		}
		canonical, err := canonicalise(object)
		if err != nil {
			return nil, err
		}
		input.Write(canonical)
	}

	return input.Bytes(), nil
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

// containsQualifyingProperties reports whether an ds:Object holds them.
func containsQualifyingProperties(object *etree.Element) bool {
	found := false
	walkElement(object, func(element *etree.Element) {
		if element.Tag == "QualifyingProperties" {
			found = true
		}
	})
	return found
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

// canonicalise returns the inclusive c14n form of an element.
func canonicalise(element *etree.Element) ([]byte, error) {
	canonicalizer := dsig.MakeC14N10RecCanonicalizer()
	canonical, err := canonicalizer.Canonicalize(element)
	if err != nil {
		return nil, fmt.Errorf("canonicalise for the archive timestamp: %w", err)
	}
	return canonical, nil
}

// buildArchiveTimeStamp emits the qualifying property in the 1.4.1 namespace.
func buildArchiveTimeStamp(signature *etree.Element, token string) string {
	return `<xades141:ArchiveTimeStamp xmlns:xades141="` + archiveNamespace + `" Id="` + idBeside(signature, "archive-timestamp") + `">` +
		`<ds:CanonicalizationMethod xmlns:ds="` + namespaceDS + `" Algorithm="` + algorithmC14N + `"/>` +
		`<xades:EncapsulatedTimeStamp xmlns:xades="` + namespaceXades + `">` + token + `</xades:EncapsulatedTimeStamp>` +
		`</xades141:ArchiveTimeStamp>`
}

// attachRevocationValues adds xades:RevocationValues (ETSI EN 319 132-1 §5.4.2).
//
// The element carries the OCSP responses and CRLs a validator needs to check the
// signature after the responders disappear. It lives in
// UnsignedSignatureProperties, so it is not covered by the signature value — which
// is exactly why XAdES-LTA then covers it with an archive timestamp.
func (s *XadesSigner) attachRevocationValues(
	ctx context.Context,
	signature *etree.Element,
	keyPair KeyPair,
) error {
	checker := verificationinfra.NewOCSPChecker()

	chain := keyPair.Certificates()
	if len(chain) == 0 {
		return fmt.Errorf("the signer carries no certificate chain to embed")
	}

	var responses [][]byte
	var warnings []string
	for index, certificate := range chain {
		if index+1 >= len(chain) {
			break
		}
		status := checker.Check(ctx, certificate, chain[index+1])
		switch {
		case status.IsRevoked():
			return fmt.Errorf(
				"refusing to sign: the certificate for %q is revoked since %s",
				certificate.Subject.CommonName, status.RevokedAt.Format(time.RFC3339))
		case status.Status == verificationdomain.RevocationGood && len(status.RawResponse) > 0:
			responses = append(responses, status.RawResponse)
		default:
			warnings = append(warnings, fmt.Sprintf("%s: %s",
				certificate.Subject.CommonName, status.Reason))
		}
	}

	if len(responses) == 0 {
		return fmt.Errorf(
			"no revocation answer could be obtained, so XAdES-LT cannot carry a complete "+
				"RevocationValues element:\n  %s", strings.Join(warnings, "\n  "))
	}

	unsigned := findUnsignedSignatureProperties(signature)
	if unsigned == nil {
		return fmt.Errorf("the signature has no xades:UnsignedSignatureProperties to extend")
	}

	fragment, err := parseFragment(buildRevocationValues(responses))
	if err != nil {
		return fmt.Errorf("build xades:RevocationValues: %w", err)
	}
	unsigned.AddChild(fragment)
	return nil
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
