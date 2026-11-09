// Package xmldsig holds the XML-Signature primitives trebaruna's XAdES signer
// and verifier share: canonical forms (W3C C14N 1.0, 1.1 and exclusive) and
// the complete check of a signature, every reference and the value over
// SignedInfo. Canonicalisers come from goxmldsig; dereferencing, transforms
// and the signature check are written here, because goxmldsig validates only
// the reference to the element it is given.
package xmldsig

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// Namespace is the XML-Signature namespace.
const Namespace = "http://www.w3.org/2000/09/xmldsig#"

// Canonicalisation and transform algorithms.
const (
	C14N10             = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	C14N10Comments     = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	C14N11             = "http://www.w3.org/2006/12/xml-c14n11"
	C14N11Comments     = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
	ExcC14N            = "http://www.w3.org/2001/10/xml-exc-c14n#"
	ExcC14NComments    = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	EnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	Base64Transform    = "http://www.w3.org/2000/09/xmldsig#base64"
	XPathTransform     = "http://www.w3.org/TR/1999/REC-xpath-19991116"
)

// withoutComments maps each canonicalisation to its variant without
// comments: a same-document reference ("" or "#id") drops comments before
// any transform runs (XML-Signature 4.4.3.3).
var withoutComments = map[string]string{
	C14N10Comments:  C14N10,
	C14N11Comments:  C14N11,
	ExcC14NComments: ExcC14N,
}

// IsCanonicalization reports a canonicalisation algorithm this package knows.
func IsCanonicalization(algorithm string) bool {
	switch algorithm {
	case C14N10, C14N10Comments, C14N11, C14N11Comments, ExcC14N, ExcC14NComments:
		return true
	}
	return false
}

// Canonicalize returns the canonical form of an element where it stands in
// its document: the namespaces and xml: attributes it inherits are part of
// it. prefixes is the InclusiveNamespaces PrefixList of exclusive C14N.
func Canonicalize(element *etree.Element, algorithm, prefixes string) ([]byte, error) {
	switch algorithm {
	case C14N10:
		return dsig.MakeC14N10RecCanonicalizer().Canonicalize(element)
	case C14N10Comments:
		return dsig.MakeC14N10WithCommentsCanonicalizer().Canonicalize(element)
	}

	// The other canonicalisers read only the element they are given, so it is
	// copied with every namespace in scope declared on it.
	context, err := etreeutils.NSBuildParentContext(element)
	if err != nil {
		return nil, err
	}
	detached, err := etreeutils.NSDetatch(context, element)
	if err != nil {
		return nil, err
	}
	switch algorithm {
	case ExcC14N:
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixes).Canonicalize(detached)
	case ExcC14NComments:
		return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixes).Canonicalize(detached)
	case C14N11:
		return dsig.MakeC14N11Canonicalizer().Canonicalize(detached)
	case C14N11Comments:
		return dsig.MakeC14N11WithCommentsCanonicalizer().Canonicalize(detached)
	}
	return nil, fmt.Errorf("%w: canonicalisation %s", ErrUnverifiable, algorithm)
}

// CanonicalizeDocument returns the canonical form of a whole document (C14N
// 1.0, 2.1): the processing instructions outside the root element, each on
// its own line before or after it, and the root. The XML declaration and the
// document type are not part of it; comments are, only when the algorithm
// keeps them.
func CanonicalizeDocument(document *etree.Document, algorithm, prefixes string) ([]byte, error) {
	root := document.Root()
	if root == nil {
		return nil, fmt.Errorf("the document has no root element")
	}
	body, err := Canonicalize(root, algorithm, prefixes)
	if err != nil {
		return nil, err
	}
	comments := strings.HasSuffix(algorithm, "#WithComments")

	var canonical bytes.Buffer
	afterRoot := false
	for _, token := range document.Child {
		var node string
		switch typed := token.(type) {
		case *etree.Element:
			canonical.Write(body)
			afterRoot = true
			continue
		case *etree.ProcInst:
			if typed.Target == "xml" {
				continue
			}
			node = "<?" + typed.Target
			if typed.Inst != "" {
				node += " " + typed.Inst
			}
			node += "?>"
		case *etree.Comment:
			if !comments {
				continue
			}
			node = "<!--" + typed.Data + "-->"
		default:
			continue
		}
		if afterRoot {
			canonical.WriteString("\n" + node)
		} else {
			canonical.WriteString(node + "\n")
		}
	}
	return canonical.Bytes(), nil
}
