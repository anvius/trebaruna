package xmldsig

import (
	"sort"
	"strings"

	"github.com/beevik/etree"
)

// mode is a canonicalisation's behaviour.
type mode struct {
	exclusive bool
	comments  bool
	// version11 inherits only xml:lang and xml:space into a subset (C14N
	// 1.1), not every xml: attribute (C14N 1.0).
	version11 bool
	// inclusive lists the prefixes exclusive C14N treats as inclusive.
	inclusive map[string]bool
}

// modeFor reads an algorithm URI.
func modeFor(algorithm, prefixes string) (mode, bool) {
	var m mode
	switch algorithm {
	case C14N10:
	case C14N10Comments:
		m.comments = true
	case C14N11:
		m.version11 = true
	case C14N11Comments:
		m.version11, m.comments = true, true
	case ExcC14N:
		m.exclusive = true
	case ExcC14NComments:
		m.exclusive, m.comments = true, true
	default:
		return mode{}, false
	}
	if m.exclusive {
		m.inclusive = map[string]bool{}
		for _, prefix := range strings.Fields(prefixes) {
			if prefix == "#default" {
				prefix = ""
			}
			m.inclusive[prefix] = true
		}
	}
	return m, true
}

// canonicalize writes an element's canonical form where it stands in its
// document (W3C Canonical XML 1.0 and 1.1, Exclusive XML Canonicalization):
// namespaces rendered once, attributes sorted by namespace URI then local
// name, text and attributes escaped as the specifications say.
func canonicalize(element *etree.Element, m mode) []byte {
	scope := map[string]string{}
	inherited := map[string]string{}
	var ancestors []*etree.Element
	for current := element.Parent(); current != nil; current = current.Parent() {
		ancestors = append([]*etree.Element{current}, ancestors...)
	}
	for _, ancestor := range ancestors {
		for _, attribute := range ancestor.Attr {
			switch {
			case attribute.Space == "xmlns":
				scope[attribute.Key] = attribute.Value
			case attribute.Space == "" && attribute.Key == "xmlns":
				scope[""] = attribute.Value
			case attribute.Space == "xml":
				inherited[attribute.Key] = attribute.Value
			}
		}
	}
	if m.exclusive {
		inherited = nil
	} else if m.version11 {
		for key := range inherited {
			if key != "lang" && key != "space" {
				delete(inherited, key)
			}
		}
	}

	var out strings.Builder
	writer := canonicalWriter{out: &out, m: m}
	writer.element(element, scope, map[string]string{}, inherited)
	return []byte(out.String())
}

// canonicalWriter writes the canonical form.
type canonicalWriter struct {
	out *strings.Builder
	m   mode
}

// element writes an element: scope is every namespace in scope above it,
// rendered the namespaces its output ancestors already wrote, inherited the
// xml: attributes the apex takes from ancestors outside the output.
func (w canonicalWriter) element(element *etree.Element, scope, rendered, inherited map[string]string) {
	inner := copyMap(scope)
	var attributes []etree.Attr
	for _, attribute := range element.Attr {
		switch {
		case attribute.Space == "xmlns":
			inner[attribute.Key] = attribute.Value
		case attribute.Space == "" && attribute.Key == "xmlns":
			inner[""] = attribute.Value
		default:
			attributes = append(attributes, attribute)
		}
	}
	attributes = withInherited(attributes, inherited)
	declarations, output := w.declarations(element, attributes, inner, rendered)
	sortAttributes(attributes, inner)

	name := qualifiedName(element.Space, element.Tag)
	w.out.WriteString("<" + name)
	for _, prefix := range declarations {
		if prefix == "" {
			w.out.WriteString(` xmlns="` + escapeAttribute(output[""]) + `"`)
			continue
		}
		w.out.WriteString(" xmlns:" + prefix + `="` + escapeAttribute(output[prefix]) + `"`)
	}
	for _, attribute := range attributes {
		w.out.WriteString(" " + qualifiedName(attribute.Space, attribute.Key) + `="` + escapeAttribute(attribute.Value) + `"`)
	}
	w.out.WriteString(">")

	for _, token := range element.Child {
		switch typed := token.(type) {
		case *etree.Element:
			w.element(typed, inner, output, nil)
		case *etree.CharData:
			w.out.WriteString(escapeText(typed.Data))
		case *etree.Comment:
			if w.m.comments {
				w.out.WriteString("<!--" + typed.Data + "-->")
			}
		case *etree.ProcInst:
			w.out.WriteString(processingInstruction(typed))
		}
	}
	w.out.WriteString("</" + name + ">")
}

// withInherited adds the inherited xml: attributes the element lacks.
func withInherited(attributes []etree.Attr, inherited map[string]string) []etree.Attr {
	for key, value := range inherited {
		present := false
		for _, attribute := range attributes {
			if attribute.Space == "xml" && attribute.Key == key {
				present = true
			}
		}
		if !present {
			attributes = append(attributes, etree.Attr{Space: "xml", Key: key, Value: value})
		}
	}
	return attributes
}

// declarations are the namespace declarations an element writes, sorted by
// prefix, and the namespaces written once it has: inclusive C14N writes
// every namespace in scope that no output ancestor wrote with that value;
// exclusive C14N only those the element and its attributes use, and the
// InclusiveNamespaces prefixes.
func (w canonicalWriter) declarations(element *etree.Element, attributes []etree.Attr, inner, rendered map[string]string) ([]string, map[string]string) {
	candidates := map[string]bool{}
	if w.m.exclusive {
		candidates[element.Space] = true
		for _, attribute := range attributes {
			if attribute.Space != "" && attribute.Space != "xml" {
				candidates[attribute.Space] = true
			}
		}
		for prefix := range w.m.inclusive {
			if _, inScope := inner[prefix]; inScope {
				candidates[prefix] = true
			}
		}
	} else {
		for prefix := range inner {
			candidates[prefix] = true
		}
	}

	var declarations []string
	output := copyMap(rendered)
	for prefix := range candidates {
		if prefix == "xml" {
			continue
		}
		value, inScope := inner[prefix]
		previous, written := rendered[prefix]
		switch {
		case prefix == "" && value == "":
			// xmlns="" undoes a default an output ancestor wrote; otherwise
			// there is nothing to undo.
			if written && previous != "" {
				declarations = append(declarations, "")
				output[""] = ""
			}
		case !inScope:
		case !written || previous != value:
			declarations = append(declarations, prefix)
			output[prefix] = value
		}
	}
	sort.Strings(declarations)
	return declarations, output
}

// sortAttributes orders attributes by namespace URI, then local name.
func sortAttributes(attributes []etree.Attr, scope map[string]string) {
	sort.SliceStable(attributes, func(i, j int) bool {
		left, right := namespaceOf(attributes[i], scope), namespaceOf(attributes[j], scope)
		if left != right {
			return left < right
		}
		return attributes[i].Key < attributes[j].Key
	})
}

// namespaceOf is an attribute's namespace URI; unqualified ones have none
// and sort first.
func namespaceOf(attribute etree.Attr, scope map[string]string) string {
	switch attribute.Space {
	case "":
		return ""
	case "xml":
		return "http://www.w3.org/XML/1998/namespace"
	}
	return scope[attribute.Space]
}

func qualifiedName(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

// processingInstruction writes <?target data?>.
func processingInstruction(instruction *etree.ProcInst) string {
	if instruction.Inst == "" {
		return "<?" + instruction.Target + "?>"
	}
	return "<?" + instruction.Target + " " + instruction.Inst + "?>"
}

// escapeText escapes character data (C14N 1.0, 2.3).
func escapeText(text string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#xD;").Replace(text)
}

// escapeAttribute escapes an attribute value (C14N 1.0, 2.3).
func escapeAttribute(text string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;", "\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;").Replace(text)
}

func copyMap(source map[string]string) map[string]string {
	copied := make(map[string]string, len(source))
	for key, value := range source {
		copied[key] = value
	}
	return copied
}
