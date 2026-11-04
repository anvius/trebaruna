package infrastructure

// Canonicalisation for trust lists.
//
// This delegates to goxmldsig's canonicaliser, which implements exclusive c14n
// correctly, and works around its one limitation: the namespace context starts
// with a traversal budget of 1000 checks, and a national trust list needs
// hundreds of thousands. Every list larger than a thousand elements failed with
// "traversal limit reached" while its signature was perfectly valid.
//
// The budget lives behind a pointer that the package shares, and there is no
// exported setter. CheckLimit is exported, however, and decrements that same
// counter, so consuming the budget before canonicalising removes the cap without
// patching the dependency. The counter is process-wide and only ever grows the
// allowance, so the effect is "no limit", which is what a 5 MB trusted list needs.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// defaultTraversalBudget is the cap goxmldsig starts with.
const defaultTraversalBudget = 1000

// errUnsupportedC14N reports a construct this package refuses to guess at.
var errUnsupportedC14N = fmt.Errorf("unsupported construct for canonicalisation")

// CanonicalizeExclusive produces the exclusive c14n form of an element.
func CanonicalizeExclusive(element *etree.Element) ([]byte, error) {
	if element == nil {
		return nil, fmt.Errorf("nothing to canonicalise")
	}

	liftTraversalLimit()

	canonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	canonical, err := canonicalizer.Canonicalize(element)
	if err != nil {
		return nil, fmt.Errorf("canonicalise: %w", err)
	}
	return canonical, nil
}

// liftTraversalLimit consumes the shared traversal budget.
//
// It is called before every canonicalisation because the counter is shared by
// all calls in the process: a previous verification may have spent part of it.
func liftTraversalLimit() {
	context := etreeutils.NewDefaultNSContext()
	for {
		if err := context.CheckLimit(); err != nil {
			return
		}
	}
}

// CanonicalizeExclusiveInContext canonicalises a subtree of a larger document.
//
// goxmldsig starts from an empty namespace context, so it only resolves the
// declarations written on the element itself. That is enough for a document root
// (which declares what it needs) and not for a SignedProperties element, whose
// xades prefix is declared on an ancestor: every such reference failed with
// "undeclared namespace prefix: xades".
//
// The fix is to resolve, for the subtree, every prefix it visibly uses against
// the ancestor declarations, and write those bindings onto a copy of the element
// before canonicalising. Exclusive c14n would emit exactly those bindings, so
// the result is the same form, just made explicit.
func CanonicalizeExclusiveInContext(element *etree.Element) ([]byte, error) {
	if element == nil {
		return nil, fmt.Errorf("nothing to canonicalise")
	}

	// Resolve the ancestor bindings once, nearest declaration winning.
	ancestors := map[string]string{}
	for current := element.Parent(); current != nil; current = current.Parent() {
		// Walking upward means the outermost is seen last, so a nearer binding
		// overwrites it, which is the correct precedence.
		for _, binding := range namespaceDeclarations(current) {
			ancestors[binding.prefix] = binding.uri
		}
	}

	// Work on a copy: the document being verified must not be modified.
	working := element.Copy()

	// Collect the prefixes this subtree uses and declare the ones it inherits.
	used := map[string]bool{}
	collectPrefixes(working, used)
	existing := map[string]bool{}
	for _, binding := range namespaceDeclarations(working) {
		existing[binding.prefix] = true
	}
	for prefix := range used {
		if existing[prefix] {
			continue
		}
		uri, known := ancestors[prefix]
		if !known {
			continue
		}
		if prefix == "" {
			working.CreateAttr("xmlns", uri)
			continue
		}
		working.CreateAttr("xmlns:"+prefix, uri)
	}

	liftTraversalLimit()

	canonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	canonical, err := canonicalizer.Canonicalize(working)
	if err != nil {
		return nil, fmt.Errorf("canonicalise in context: %w", err)
	}
	return canonical, nil
}

// collectPrefixes records every namespace prefix used in a subtree.
func collectPrefixes(element *etree.Element, prefixes map[string]bool) {
	if element.Space != "" {
		prefixes[element.Space] = true
	}
	for _, attribute := range element.Attr {
		if attribute.Space != "" && attribute.Space != "xmlns" {
			prefixes[attribute.Space] = true
		}
		if attribute.Space == "" && attribute.Key == "xmlns" {
			prefixes[""] = true
		}
	}
	for _, child := range element.ChildElements() {
		collectPrefixes(child, prefixes)
	}
}

// digestOfElement returns the base64 SHA-256 of the exclusive c14n form.
func digestOfElement(element *etree.Element) (string, error) {
	canonical, err := CanonicalizeExclusive(element)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

var _ = bytes.MinRead

// namespaceBinding is one xmlns declaration.
type namespaceBinding struct {
	prefix string
	uri    string
}

// namespaceDeclarations reads the xmlns declarations on one element.
//
// etree spells these two ways, which is worth stating because getting it wrong
// silently drops the default namespace:
//
//	xmlns="uri"    -> Space="",      Key="xmlns"
//	xmlns:ns3="u"  -> Space="xmlns", Key="ns3"
func namespaceDeclarations(element *etree.Element) []namespaceBinding {
	if element == nil {
		return nil
	}

	var declarations []namespaceBinding
	for _, attribute := range element.Attr {
		if attribute.Space == "" && attribute.Key == "xmlns" {
			declarations = append(declarations, namespaceBinding{prefix: "", uri: attribute.Value})
			continue
		}
		if attribute.Space == "xmlns" {
			declarations = append(declarations, namespaceBinding{prefix: attribute.Key, uri: attribute.Value})
		}
	}
	return declarations
}

// mergeDeclarations applies new bindings over inherited ones.
func mergeDeclarations(inherited, declared []namespaceBinding) []namespaceBinding {
	merged := append([]namespaceBinding{}, inherited...)

	for _, binding := range declared {
		replaced := false
		for index := range merged {
			if merged[index].prefix == binding.prefix {
				merged[index].uri = binding.uri
				replaced = true
				break
			}
		}
		if !replaced {
			merged = append(merged, binding)
		}
	}
	return merged
}
