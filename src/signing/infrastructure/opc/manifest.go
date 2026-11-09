package opc

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// SignatureParts lists the signature parts the package's origin points at:
// the signatures of the package, in the order its relationships give them.
func (p *Package) SignatureParts() ([]string, error) {
	roots, err := p.relationships("/")
	if err != nil {
		return nil, err
	}
	var signatures []string
	for _, relationship := range roots {
		if relationship.Type != typeOrigin || relationship.external() {
			continue
		}
		origin := relationship.targetPart("/")
		linked, err := p.relationships(origin)
		if err != nil {
			return nil, err
		}
		for _, signature := range linked {
			if signature.Type == typeSignature && !signature.external() {
				signatures = append(signatures, signature.targetPart(origin))
			}
		}
	}
	return signatures, nil
}

// ManifestCheck is what CheckManifest found.
type ManifestCheck struct {
	// Covered are the parts the Manifest lists, each matching its digest.
	Covered []string
	// LibxmlsecForm are the relationships parts whose digest matches the
	// form libxmlsec's transform yields (LibreOffice's), not ECMA-376's.
	LibxmlsecForm []string
}

// CheckManifest compares every part a signature's Manifest lists with its
// digest. Parts missing from the package, declared with another content
// type, or whose digest differs, are named in one xmldsig.ErrModified; a
// transform or digest this package does not know is
// xmldsig.ErrUnverifiable. Every listed part counts as covered.
func (p *Package) CheckManifest(manifest *etree.Element) (ManifestCheck, error) {
	var check ManifestCheck
	var faults []string
	var unverifiable error
	for _, reference := range manifest.ChildElements() {
		if reference.Tag != "Reference" || reference.NamespaceURI() != xmldsig.Namespace {
			continue
		}
		name, data, alternative, err := p.referenced(reference)
		check.Covered = append(check.Covered, name)
		var fault partFault
		switch {
		case errors.As(err, &fault):
			faults = append(faults, string(fault))
			continue
		case err != nil:
			unverifiable = cmp.Or(unverifiable, err)
			continue
		}
		matched, err := matchesDigest(reference, data)
		if err != nil {
			unverifiable = cmp.Or(unverifiable, err)
			continue
		}
		if !matched && alternative != nil {
			if matched, _ = matchesDigest(reference, alternative); matched {
				check.LibxmlsecForm = append(check.LibxmlsecForm, name)
			}
		}
		if !matched {
			faults = append(faults, name)
		}
	}
	if len(faults) > 0 {
		return check, fmt.Errorf("%w: %s", xmldsig.ErrModified, strings.Join(faults, "; "))
	}
	return check, unverifiable
}

// partFault is a part that does not match the reference to it.
type partFault string

func (f partFault) Error() string { return string(f) }

// matchesDigest compares octets with a reference's digest.
func matchesDigest(reference *etree.Element, octets []byte) (bool, error) {
	method, value := reference.SelectElement("DigestMethod"), reference.SelectElement("DigestValue")
	if method == nil || value == nil {
		return false, nil
	}
	expected, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value.Text()), ""))
	if err != nil {
		return false, nil
	}
	digest, err := xmldsig.Digest(method.SelectAttrValue("Algorithm", ""), octets)
	return err == nil && bytes.Equal(digest, expected), err
}

// referenced resolves a Manifest reference to its part and applies its
// transforms: none, or the RelationshipTransform followed by a
// canonicalisation, as Office writes them. For a relationships part with
// text between its relationships, alternative is libxmlsec's form of the
// same transform.
func (p *Package) referenced(reference *etree.Element) (name string, data, alternative []byte, err error) {
	name, contentType, typed := strings.Cut(reference.SelectAttrValue("URI", ""), "?ContentType=")
	data, found := p.Part(name)
	switch {
	case !strings.HasPrefix(name, "/"):
		return name, nil, nil, fmt.Errorf("%w: %q is not a part of the package", xmldsig.ErrUnverifiable, name)
	case !found:
		return name, nil, nil, partFault(name + " is missing from the package")
	case typed && !strings.EqualFold(contentType, p.ContentType(name)):
		return name, nil, nil, partFault(fmt.Sprintf("%s was signed as %s and is declared as %s", name, contentType, p.ContentType(name)))
	}

	var transforms []*etree.Element
	if container := reference.SelectElement("Transforms"); container != nil {
		transforms = container.SelectElements("Transform")
	}
	if len(transforms) > 0 && transforms[0].SelectAttrValue("Algorithm", "") == RelationshipTransform {
		var ids, types []string
		for _, selector := range transforms[0].ChildElements() {
			switch selector.Tag {
			case "RelationshipReference":
				ids = append(ids, selector.SelectAttrValue("SourceId", ""))
			case "RelationshipsGroupReference":
				types = append(types, selector.SelectAttrValue("SourceType", ""))
			}
		}
		transformed, err := TransformRelationships(data, ids, types)
		if err != nil {
			return name, nil, nil, partFault(name + " is not a relationships part")
		}
		alternative, _ = libxmlsecForm(data, transformed)
		data, transforms = transformed, transforms[1:]
	}
	for _, transform := range transforms {
		algorithm := transform.SelectAttrValue("Algorithm", "")
		if !xmldsig.IsCanonicalization(algorithm) {
			return name, nil, nil, fmt.Errorf("%w: transform %s on %s", xmldsig.ErrUnverifiable, algorithm, name)
		}
		document := etree.NewDocument()
		if err := document.ReadFromBytes(data); err != nil {
			return name, nil, nil, partFault(name + " is not XML")
		}
		if data, err = xmldsig.CanonicalizeDocument(document, algorithm, ""); err != nil {
			return name, nil, nil, err
		}
	}
	return name, data, alternative, nil
}

// Manifests are the Manifest elements of a signature part.
func Manifests(document *etree.Document) []*etree.Element {
	var found []*etree.Element
	var walk func(*etree.Element)
	walk = func(element *etree.Element) {
		if element.Tag == "Manifest" && element.NamespaceURI() == xmldsig.Namespace {
			found = append(found, element)
		}
		for _, child := range element.ChildElements() {
			walk(child)
		}
	}
	if document.Root() != nil {
		walk(document.Root())
	}
	return found
}

// followsLibxmlsec reports a package one of whose signatures digested its
// relationships in libxmlsec's form: a new signature does the same, so all
// of them verify in the same applications.
func (p *Package) followsLibxmlsec() bool {
	parts, err := p.SignatureParts()
	if err != nil {
		return false
	}
	for _, part := range parts {
		content, found := p.Part(part)
		document := etree.NewDocument()
		if !found || document.ReadFromBytes(content) != nil {
			continue
		}
		for _, manifest := range Manifests(document) {
			if check, _ := p.CheckManifest(manifest); len(check.LibxmlsecForm) > 0 {
				return true
			}
		}
	}
	return false
}

// Unsigned lists the parts no signature covers, but for the signatures
// themselves and the metadata Office leaves out of its own (document
// properties, thumbnail): a part added after signing, or one a signature
// skipped, is named.
func (p *Package) Unsigned(covered map[string]bool) []string {
	skipped := map[string]bool{}
	if roots, err := p.relationships("/"); err == nil {
		for _, relationship := range roots {
			if metadata[relationship.Type] && !relationship.external() {
				skipped[fold(relationship.targetPart("/"))] = true
			}
		}
	}
	folded := map[string]bool{}
	for name := range covered {
		folded[fold(name)] = true
	}
	var unsigned []string
	for _, name := range p.names {
		key := fold(name)
		if folded[key] || skipped[key] || p.isSignaturePart(name) ||
			(isRelationshipsPart(name) && skipped[fold(relationshipsSource(name))]) {
			continue
		}
		unsigned = append(unsigned, strings.TrimPrefix(name, "/"))
	}
	return unsigned
}
