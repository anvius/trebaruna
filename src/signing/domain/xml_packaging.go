package domain

// XMLPackaging is how an XML signature holds what it signs.
type XMLPackaging string

const (
	// XMLEnveloped puts the signature inside the XML document it signs.
	XMLEnveloped XMLPackaging = "enveloped"
	// XMLEnveloping carries the document inside the signature.
	XMLEnveloping XMLPackaging = "enveloping"
	// XMLDetached leaves the document untouched beside the signature, which
	// names it.
	XMLDetached XMLPackaging = "detached"
	// XMLInternallyDetached is AutoFirma's "XAdES Detached": a new document
	// whose root holds the content and, beside it, the signature.
	XMLInternallyDetached XMLPackaging = "internally-detached"
)

// NeedsXML reports a packaging that only signs XML documents: an enveloped
// signature goes inside the document, so the document must be XML.
func (p XMLPackaging) NeedsXML() bool { return p == XMLEnveloped || p == "" }
