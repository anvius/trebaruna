package opc

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// TransformRelationships applies the RelationshipTransform (ECMA-376 Part
// 2, §13.2.4.24) to a relationships part and returns its canonical form
// (C14N 1.0), the octets a signature digests. Only the relationships
// selected by Id or by type are kept, sorted by Id, with Id, Target,
// TargetMode (Internal when absent) and Type and nothing else: a
// relationship added to the part later, or the part reformatted, leaves the
// digest as it was.
func TransformRelationships(content []byte, ids, types []string) ([]byte, error) {
	relationships, err := parseRelationships(content)
	if err != nil {
		return nil, err
	}
	selectedIDs, selectedTypes := setOf(ids), setOf(types)
	var kept []Relationship
	for _, relationship := range relationships {
		if selectedIDs[relationship.ID] || selectedTypes[relationship.Type] {
			kept = append(kept, relationship)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].ID < kept[j].ID })

	document := etree.NewDocument()
	root := document.CreateElement("Relationships")
	root.CreateAttr("xmlns", namespaceRelationships)
	for _, relationship := range kept {
		mode := relationship.TargetMode
		if mode == "" {
			mode = "Internal"
		}
		element := root.CreateElement("Relationship")
		element.CreateAttr("Id", relationship.ID)
		element.CreateAttr("Target", relationship.Target)
		element.CreateAttr("TargetMode", mode)
		element.CreateAttr("Type", relationship.Type)
	}
	return xmldsig.CanonicalizeDocument(document, xmldsig.C14N10, "")
}

// libxmlsecForm is what libxmlsec's RelationshipTransform yields instead,
// the one LibreOffice signs and verifies with: every text or comment node
// between the relationships written as an empty element named after the
// node (<text></text>) and sorted first, where ECMA-376 removes them. Over
// a part written without them, both forms are the same. spec is
// TransformRelationships' output for the same part.
func libxmlsecForm(content, spec []byte) ([]byte, bool) {
	document := etree.NewDocument()
	if err := document.ReadFromBytes(content); err != nil || document.Root() == nil {
		return nil, false
	}
	var nodes strings.Builder
	for _, token := range document.Root().Child {
		switch token.(type) {
		case *etree.CharData:
			nodes.WriteString("<text></text>")
		case *etree.Comment:
			nodes.WriteString("<comment></comment>")
		}
	}
	if nodes.Len() == 0 {
		return nil, false
	}
	start := bytes.IndexByte(spec, '>') + 1
	return append(append(append([]byte{}, spec[:start]...), nodes.String()...), spec[start:]...), true
}

// compactRelationships writes a relationships part without the text and
// comments between its relationships, as Office writes it: the same
// relationships, and a digest every implementation of the transform agrees
// on.
func compactRelationships(content []byte) ([]byte, bool, error) {
	document := etree.NewDocument()
	if err := document.ReadFromBytes(content); err != nil || document.Root() == nil {
		return nil, false, fmt.Errorf("%w: unreadable relationships part", ErrNotPackage)
	}
	root := document.Root()
	var loose []etree.Token
	for _, token := range root.Child {
		switch token.(type) {
		case *etree.CharData, *etree.Comment:
			loose = append(loose, token)
		}
	}
	if len(loose) == 0 {
		return content, false, nil
	}
	for _, token := range loose {
		root.RemoveChild(token)
	}
	compact, err := document.WriteToBytes()
	return compact, true, err
}

// withRelationship adds a relationship to a relationships part (nil for a
// new one), under the first Id the part does not use.
func withRelationship(content []byte, relationshipType, target string) ([]byte, error) {
	document := etree.NewDocument()
	if content == nil {
		document.CreateProcInst("xml", `version="1.0" encoding="UTF-8" standalone="yes"`)
		document.CreateElement("Relationships").CreateAttr("xmlns", namespaceRelationships)
	} else if err := document.ReadFromBytes(content); err != nil || document.Root() == nil {
		return nil, fmt.Errorf("%w: unreadable relationships part", ErrNotPackage)
	}
	used := map[string]bool{}
	for _, element := range document.Root().ChildElements() {
		used[element.SelectAttrValue("Id", "")] = true
	}
	id := "rId1"
	for number := 2; used[id]; number++ {
		id = "rId" + strconv.Itoa(number)
	}
	element := document.Root().CreateElement("Relationship")
	element.Space = document.Root().Space
	element.CreateAttr("Id", id)
	element.CreateAttr("Type", relationshipType)
	element.CreateAttr("Target", target)
	return document.WriteToBytes()
}

func setOf(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}
