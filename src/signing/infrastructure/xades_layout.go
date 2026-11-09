package infrastructure

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// objectType is the Type of a reference to a ds:Object.
const objectType = "http://www.w3.org/2000/09/xmldsig#Object"

// documentLayout says how a signature holds what it signs, decided before
// any XML is written.
type documentLayout struct {
	packaging domain.XMLPackaging
	// plain is XMLDSig: the document reference alone, no signed properties.
	plain bool
	// excludeSignatures leaves every signature out of an enveloped reference
	// (AutoFirma's XPath filter), so a signature added later to the document
	// does not break this one. FacturaE invoices take one signature and
	// AutoFirma writes none.
	excludeSignatures bool
	// xml is the content read as XML; nil for other bytes, which travel in
	// Base64 inside the signature.
	xml *etree.Document
	// mimeType describes the content in DataObjectFormat.
	mimeType string
	// uri is the reference to the document beside a detached signature.
	uri string
}

// layoutFor reads the content once: XML is signed as XML (inside the
// document, an Object or AutoFirma's CONTENT), anything else as its bytes.
// The media type is sniffed from the content, as AutoFirma does.
func layoutFor(request application.XadesRequest) (documentLayout, error) {
	layout := documentLayout{
		packaging:         request.Packaging,
		plain:             request.Plain,
		excludeSignatures: !request.Policy.IsFacturaE(),
		uri:               url.PathEscape(request.DocumentName),
	}
	if layout.packaging == "" {
		layout.packaging = domain.XMLEnveloped
	}
	if document, err := parseDocument(request.Content); err == nil {
		layout.xml, layout.mimeType = document, "text/xml"
	} else {
		layout.mimeType = mediaType(request.Content)
	}
	switch {
	case layout.packaging.NeedsXML() && layout.xml == nil:
		return documentLayout{}, fmt.Errorf("an enveloped XML signature goes inside an XML document; this one is not XML")
	case layout.packaging == domain.XMLDetached && request.DocumentName == "":
		return documentLayout{}, fmt.Errorf("a detached XML signature names its document, and none was given")
	}
	return layout, nil
}

// mediaType sniffs the media type of bytes, without its parameters.
func mediaType(content []byte) string {
	detected := http.DetectContentType(content)
	if semicolon := strings.Index(detected, ";"); semicolon >= 0 {
		detected = detected[:semicolon]
	}
	return strings.TrimSpace(detected)
}

// referenceCount is how many references SignedInfo holds: the document,
// and the signed properties unless the signature is plain XMLDSig.
func (l documentLayout) referenceCount() int {
	if l.plain {
		return 1
	}
	return 2
}

// inBase64 reports content that travels in Base64 inside the signature.
func (l documentLayout) inBase64() bool {
	return l.xml == nil && (l.packaging == domain.XMLEnveloping || l.packaging == domain.XMLInternallyDetached)
}

// tree is the document the signature is attached to: the signed XML itself
// (enveloped), AutoFirma's AFIRMA root holding CONTENT (internally detached),
// or an empty document the signature becomes the root of.
func (l documentLayout) tree(ids signatureIDs, content []byte) *etree.Document {
	switch l.packaging {
	case domain.XMLEnveloped:
		return l.xml
	case domain.XMLInternallyDetached:
		tree := etree.NewDocument()
		root := tree.CreateElement("AFIRMA")
		root.CreateAttr("Id", ids.afirmaRoot())
		holder := root.CreateElement("CONTENT")
		holder.CreateAttr("Id", ids.content())
		holder.CreateAttr("MimeType", l.mimeType)
		if l.xml != nil {
			holder.AddChild(l.xml.Root().Copy())
			return tree
		}
		holder.CreateAttr("Encoding", encodingBase64)
		holder.SetText(base64.StdEncoding.EncodeToString(content))
		return tree
	}
	return etree.NewDocument()
}

// payload is the ds:Object an enveloping signature carries the content in.
func (l documentLayout) payload(ids signatureIDs, content []byte) (string, error) {
	if l.packaging != domain.XMLEnveloping {
		return "", nil
	}
	if l.xml != nil {
		holder := etree.NewDocument()
		holder.SetRoot(l.xml.Root().Copy())
		inner, err := holder.WriteToString()
		if err != nil {
			return "", err
		}
		return `<ds:Object Id="` + ids.payload() + `" MimeType="text/xml">` + inner + `</ds:Object>`, nil
	}
	return `<ds:Object Id="` + ids.payload() + `" MimeType="` + xmlEscape(l.mimeType) + `" Encoding="` + encodingBase64 + `">` +
		base64.StdEncoding.EncodeToString(content) + `</ds:Object>`, nil
}

// documentReference is the reference to what the signature signs.
//
// Enveloped signatures reference the whole document with URI="" and must
// declare the enveloped-signature transform, or a verifier hashes the
// document with the signature inside. Enveloping and internally detached
// ones reference the element holding the content: Base64 is decoded so the
// digest is the document's own, XML is canonicalised. A detached signature
// names the file beside it and digests its bytes.
func (l documentLayout) documentReference(ids signatureIDs) string {
	var uri, referenceType, transforms string
	switch l.packaging {
	case domain.XMLEnveloping:
		uri, referenceType, transforms = "#"+ids.payload(), objectType, l.contentTransform()
	case domain.XMLInternallyDetached:
		uri, transforms = "#"+ids.content(), l.contentTransform()
	case domain.XMLDetached:
		uri = l.uri
	default:
		filter := ""
		if l.excludeSignatures {
			filter = `<ds:Transform Algorithm="` + xmldsig.XPathTransform + `">` +
				`<ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform>`
		}
		transforms = `<ds:Transform Algorithm="` + algorithmEnveloped + `"/>` + filter +
			`<ds:Transform Algorithm="` + algorithmC14N + `"/>`
	}

	reference := `<ds:Reference Id="` + ids.reference() + `"`
	if referenceType != "" {
		reference += ` Type="` + referenceType + `"`
	}
	reference += ` URI="` + xmlEscape(uri) + `">`
	if transforms != "" {
		reference += `<ds:Transforms>` + transforms + `</ds:Transforms>`
	}
	return reference +
		`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
		`<ds:DigestValue>` + placeholderDigest + `</ds:DigestValue>` +
		`</ds:Reference>`
}

// contentTransform turns the element holding the content back into it.
func (l documentLayout) contentTransform() string {
	if l.inBase64() {
		return `<ds:Transform Algorithm="` + xmldsig.Base64Transform + `"/>`
	}
	return `<ds:Transform Algorithm="` + algorithmC14N + `"/>`
}

// dataObjectFormat describes the signed content (EN 319 132-1, B-B).
func (l documentLayout) dataObjectFormat() string {
	format := `<xades:MimeType>` + xmlEscape(l.mimeType) + `</xades:MimeType>`
	if l.inBase64() {
		format += `<xades:Encoding>` + encodingBase64 + `</xades:Encoding>`
	}
	return format
}

// resolver hands the content to the reference of a detached signature.
func (l documentLayout) resolver(content []byte) xmldsig.Resolver {
	if l.packaging != domain.XMLDetached {
		return nil
	}
	return func(uri string) ([]byte, error) {
		if uri != l.uri {
			return nil, fmt.Errorf("%w: %s", xmldsig.ErrContentMissing, uri)
		}
		return content, nil
	}
}
