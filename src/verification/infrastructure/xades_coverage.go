package infrastructure

import (
	"strings"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// describeCoverage names the parts of the document around a signature that
// none of its references covers. A signature whose references point at one
// element by Id leaves the rest unsigned, and that rest is what a reader
// sees too: the ground of signature wrapping attacks. Nothing is said when
// a reference covers the whole document (URI=""), or when the document is
// the signature itself (detached and enveloping signatures).
func describeCoverage(document *etree.Document, signature *etree.Element, report *domain.SignerReport) {
	root := document.Root()
	if root == nil || root == signature || countersigned(document, signature) != nil {
		return
	}
	covered := map[*etree.Element]bool{}
	for _, reference := range signature.FindElements("./SignedInfo/Reference") {
		uri := reference.SelectAttrValue("URI", "")
		switch {
		case uri == "":
			return
		case strings.HasPrefix(uri, "#"):
			if element, err := xmldsig.ElementByID(root, uri[1:]); err == nil {
				covered[element] = true
			}
		}
	}
	if covered[root] {
		return
	}
	// The elements that hold a covered one are walked into; the rest are
	// unsigned as a whole.
	holdsCovered := map[*etree.Element]bool{}
	for element := range covered {
		for parent := element.Parent(); parent != nil; parent = parent.Parent() {
			holdsCovered[parent] = true
		}
	}
	var unsigned []string
	var visit func(element *etree.Element, path string)
	visit = func(element *etree.Element, path string) {
		for _, child := range element.ChildElements() {
			childPath := path + "/" + qualifiedTag(child)
			switch {
			case covered[child] || isSignature(child):
			case holdsCovered[child]:
				visit(child, childPath)
			default:
				unsigned = append(unsigned, childPath)
			}
		}
	}
	visit(root, "/"+qualifiedTag(root))
	if len(unsigned) == 0 {
		return
	}
	report.Findings = append(report.Findings, domain.Finding{
		Code:    "content.partly_signed",
		Status:  domain.StatusWarn,
		Message: "the signature covers only part of the document: these parts are not signed",
		Detail:  strings.Join(unsigned, ", "),
	})
}

func isSignature(element *etree.Element) bool {
	return element.Tag == "Signature" && element.NamespaceURI() == xmldsig.Namespace
}

func qualifiedTag(element *etree.Element) string {
	if element.Space == "" {
		return element.Tag
	}
	return element.Space + ":" + element.Tag
}

// typeCountersignedSignature marks a counter-signature's reference.
const typeCountersignedSignature = "http://uri.etsi.org/01903#CountersignedSignature"

// countersigned is the signature a counter-signature signs: the one holding
// it, whose SignatureValue its CountersignedSignature reference names.
// Anything else is not a counter-signature.
func countersigned(document *etree.Document, signature *etree.Element) *etree.Element {
	var holder *etree.Element
	for parent := signature.Parent(); parent != nil; parent = parent.Parent() {
		if isSignature(parent) {
			holder = parent
			break
		}
	}
	if holder == nil {
		return nil
	}
	for _, reference := range signature.FindElements("./SignedInfo/Reference") {
		uri := reference.SelectAttrValue("URI", "")
		if reference.SelectAttrValue("Type", "") != typeCountersignedSignature || !strings.HasPrefix(uri, "#") {
			continue
		}
		value, err := xmldsig.ElementByID(document.Root(), uri[1:])
		if err == nil && value.Tag == "SignatureValue" && value.Parent() == holder {
			return holder
		}
	}
	return nil
}
