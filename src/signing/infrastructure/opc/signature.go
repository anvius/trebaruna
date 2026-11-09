package opc

import (
	"archive/zip"
	"bytes"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Reference is a part a signature's Manifest lists.
type Reference struct {
	// URI names the part and its content type, as Office writes it:
	// /word/document.xml?ContentType=application/vnd…main+xml.
	URI string
	// Relationships are the Ids a relationships part is signed for, through
	// the RelationshipTransform; nil for any other part.
	Relationships []string
	// Data are the octets digested: the part as it is, or the transform's
	// output for a relationships part.
	Data []byte
}

// CompactRelationships writes the relationships parts of a package that
// carries no signature yet without the text between their relationships,
// as Office writes them. ECMA-376's RelationshipTransform ignores that
// text and libxmlsec's (LibreOffice's) does not, so over a compact part
// both agree on the digest and the signature verifies in either. A signed
// package is left as it is: its signatures were digested over those bytes.
func (p *Package) CompactRelationships() error {
	if signatures, err := p.SignatureParts(); err != nil || len(signatures) > 0 {
		return err
	}
	for _, name := range p.names {
		if !isRelationshipsPart(name) || p.isSignaturePart(name) {
			continue
		}
		compact, changed, err := compactRelationships(p.parts[fold(name)])
		if err != nil {
			return err
		}
		if changed {
			p.parts[fold(name)], p.rewritten[fold(name)] = compact, true
		}
	}
	return nil
}

// SignedReferences lists what a new signature covers, as LibreOffice
// chooses it: every part but the signatures and the left-out document
// properties; a relationships part through the RelationshipTransform, for
// every relationship but the left-out ones. When an earlier signature
// digested the relationships in libxmlsec's form, so does this one.
func (p *Package) SignedReferences() ([]Reference, error) {
	excluded, err := p.leftOutParts()
	if err != nil {
		return nil, err
	}
	follow := p.followsLibxmlsec()
	var references []Reference
	for _, name := range p.names {
		if excluded[fold(name)] || p.isSignaturePart(name) ||
			(isRelationshipsPart(name) && excluded[fold(relationshipsSource(name))]) {
			continue
		}
		contentType := p.ContentType(name)
		if contentType == "" {
			return nil, fmt.Errorf("%w: %s has no content type", ErrNotPackage, name)
		}
		reference := Reference{URI: name + "?ContentType=" + contentType, Data: p.parts[fold(name)]}
		if isRelationshipsPart(name) {
			relationships, err := parseRelationships(reference.Data)
			if err != nil {
				return nil, err
			}
			for _, relationship := range relationships {
				if !leftOut[relationship.Type] {
					reference.Relationships = append(reference.Relationships, relationship.ID)
				}
			}
			if len(reference.Relationships) == 0 {
				continue
			}
			transformed, err := TransformRelationships(reference.Data, reference.Relationships, nil)
			if err != nil {
				return nil, err
			}
			if alternative, loose := libxmlsecForm(reference.Data, transformed); follow && loose {
				transformed = alternative
			}
			reference.Data = transformed
		}
		references = append(references, reference)
	}
	return references, nil
}

// leftOutParts are the targets of the package's left-out relationships.
func (p *Package) leftOutParts() (map[string]bool, error) {
	relationships, err := p.relationships("/")
	if err != nil {
		return nil, err
	}
	parts := map[string]bool{}
	for _, relationship := range relationships {
		if leftOut[relationship.Type] && !relationship.external() {
			parts[fold(relationship.targetPart("/"))] = true
		}
	}
	return parts, nil
}

// isSignaturePart reports the signature machinery: the origin, the
// signatures and their certificates, and the origin's relationships.
func (p *Package) isSignaturePart(name string) bool {
	switch p.ContentType(name) {
	case contentTypeOrigin, contentTypeSignature, contentTypeCertificate:
		return true
	}
	if isRelationshipsPart(name) {
		return p.ContentType(relationshipsSource(name)) == contentTypeOrigin
	}
	return strings.HasPrefix(fold(name), "/_xmlsignatures/")
}

// WithSignature returns the package with one more signature part, linked
// from the signatures' origin (created when there is none) and declared in
// [Content_Types].xml. The parts signatures cover are copied untouched, so
// earlier signatures stay valid.
func (p *Package) WithSignature(signature []byte) ([]byte, error) {
	changes := edit{pkg: p, content: map[string][]byte{}, names: map[string]string{}}
	for _, name := range p.names {
		if p.rewritten[fold(name)] {
			changes.set(name, p.parts[fold(name)])
		}
	}

	origin := ""
	roots, err := p.relationships("/")
	if err != nil {
		return nil, err
	}
	for _, relationship := range roots {
		if relationship.Type == typeOrigin && !relationship.external() {
			origin = relationship.targetPart("/")
		}
	}
	if origin == "" {
		origin = "/_xmlsignatures/origin.sigs"
		rootRelationships, _ := p.Part(relationshipsPart("/"))
		updated, err := withRelationship(rootRelationships, typeOrigin, strings.TrimPrefix(origin, "/"))
		if err != nil {
			return nil, err
		}
		changes.set(relationshipsPart("/"), updated)
	}
	if _, exists := p.Part(origin); !exists {
		changes.set(origin, []byte{})
	}

	name := ""
	for number := 1; name == ""; number++ {
		candidate := path.Join(path.Dir(origin), "sig"+strconv.Itoa(number)+".xml")
		if _, exists := p.Part(candidate); !exists {
			name = candidate
		}
	}
	originRelationships, _ := p.Part(relationshipsPart(origin))
	updated, err := withRelationship(originRelationships, typeSignature, path.Base(name))
	if err != nil {
		return nil, err
	}
	changes.set(relationshipsPart(origin), updated)
	changes.set(name, signature)

	types, err := p.withContentTypes(origin, name)
	if err != nil {
		return nil, err
	}
	return p.rewrite(types, changes)
}

// edit holds the parts a new signature changes or adds, by folded name.
type edit struct {
	pkg     *Package
	content map[string][]byte
	names   map[string]string
	// added are the new parts, in the order they were set.
	added []string
}

func (e *edit) set(name string, content []byte) {
	key := fold(name)
	if _, exists := e.pkg.parts[key]; !exists && e.names[key] == "" {
		e.added = append(e.added, key)
	}
	e.names[key], e.content[key] = name, content
}

// withContentTypes declares the origin, when nothing does yet, and the new
// signature part.
func (p *Package) withContentTypes(origin, signature string) ([]byte, error) {
	document := etree.NewDocument()
	if err := document.ReadFromBytes(p.contentTypes); err != nil || document.Root() == nil {
		return nil, fmt.Errorf("%w: unreadable %s", ErrNotPackage, contentTypesName)
	}
	root := document.Root()
	declare := func(tag, key, value, contentType string) {
		element := root.CreateElement(tag)
		element.Space = root.Space
		element.CreateAttr(key, value)
		element.CreateAttr("ContentType", contentType)
	}
	if p.ContentType(origin) == "" {
		if strings.EqualFold(path.Ext(origin), ".sigs") {
			declare("Default", "Extension", "sigs", contentTypeOrigin)
		} else {
			declare("Override", "PartName", origin, contentTypeOrigin)
		}
	}
	declare("Override", "PartName", signature, contentTypeSignature)
	return document.WriteToBytes()
}

// rewrite copies the package entry by entry, replacing the changed parts
// where they stand and adding the new ones at the end.
func (p *Package) rewrite(types []byte, changes edit) ([]byte, error) {
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range p.archive.File {
		content, changed := changes.content[fold("/"+entry.Name)]
		if entry.Name == contentTypesName {
			content, changed = types, true
		}
		var err error
		if changed {
			err = writeDeflated(writer, entry.Name, content)
		} else {
			err = writer.Copy(entry)
		}
		if err != nil {
			return nil, err
		}
	}
	for _, key := range changes.added {
		if err := writeDeflated(writer, strings.TrimPrefix(changes.names[key], "/"), changes.content[key]); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeDeflated(writer *zip.Writer, name string, content []byte) error {
	// A dated entry: a zero MS-DOS date (month 0) is no date at all.
	entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
	if err != nil {
		return err
	}
	_, err = entry.Write(content)
	return err
}
