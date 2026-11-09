// Package opc reads Open Packaging Conventions packages (ECMA-376 Part 2),
// the ZIP behind .docx, .xlsx and .pptx files: their parts, the content
// type of each, the relationships between them, and the digital signatures
// the conventions define (§13). The signer and the verifier share it, so a
// part is digested the same way on both sides.
package opc

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/beevik/etree"
)

// Names the conventions fix.
const (
	contentTypesName      = "[Content_Types].xml"
	namespaceContentTypes = "http://schemas.openxmlformats.org/package/2006/content-types"

	// namespaceRelationships is the namespace of relationships parts.
	namespaceRelationships = "http://schemas.openxmlformats.org/package/2006/relationships"
	// NamespaceSignature is the namespace of OPC's signature elements:
	// RelationshipReference and SignatureTime.
	NamespaceSignature = "http://schemas.openxmlformats.org/package/2006/digital-signature"
	// RelationshipTransform is the transform a signature applies to a
	// relationships part (§13.2.4.24).
	RelationshipTransform = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform"

	typeOrigin    = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin"
	typeSignature = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature"

	contentTypeOrigin      = "application/vnd.openxmlformats-package.digital-signature-origin"
	contentTypeSignature   = "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"
	contentTypeCertificate = "application/vnd.openxmlformats-package.digital-signature-certificate"

	// partLimit bounds each part: a package is read whole, and a crafted
	// one must not exhaust memory.
	partLimit = 512 << 20
)

// Relationship types the signature rules name.
const (
	typeCoreProperties     = "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
	typeExtendedProperties = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties"
	typeCustomProperties   = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties"
	typeThumbnail          = "http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail"
)

// leftOut are the relationships a new signature leaves out, as LibreOffice
// does (OOXMLSecExporter): those to the core and extended document
// properties, which applications rewrite when they save, and the one to
// the signatures' origin. Their targets are not signed either.
var leftOut = map[string]bool{typeCoreProperties: true, typeExtendedProperties: true, typeOrigin: true}

// metadata are the relationships to parts Microsoft Office's own
// signatures do not cover either; a verifier does not call them unsigned.
var metadata = map[string]bool{
	typeCoreProperties: true, typeExtendedProperties: true, typeCustomProperties: true, typeThumbnail: true,
}

// ErrNotPackage means bytes that are not an Office Open XML package.
var ErrNotPackage = errors.New("not an Office Open XML package")

// Package is a package read whole.
type Package struct {
	archive *zip.Reader
	// names are the part names in ZIP order, each with its leading slash.
	names []string
	// parts are the contents, by folded part name: part names compare
	// without regard to ASCII case (§9.1.1.1).
	parts     map[string][]byte
	defaults  map[string]string
	overrides map[string]string
	// contentTypes is [Content_Types].xml as read.
	contentTypes []byte
	// rewritten are the parts changed since the package was read, by
	// folded name: written anew when the package is.
	rewritten map[string]bool
}

// Relationship is one relationship of a source part. TargetMode is as
// written: empty means Internal.
type Relationship struct {
	ID, Type, Target, TargetMode string
}

// External reports a relationship to a resource outside the package.
func (r Relationship) external() bool { return r.TargetMode == "External" }

// Open reads a package.
func Open(content []byte) (*Package, error) {
	archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotPackage, err)
	}
	pkg := &Package{archive: archive, parts: map[string][]byte{}, defaults: map[string]string{},
		overrides: map[string]string{}, rewritten: map[string]bool{}}
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		data, err := readEntry(entry)
		if err != nil {
			return nil, err
		}
		if entry.Name == contentTypesName {
			pkg.contentTypes = data
			continue
		}
		name := "/" + entry.Name
		pkg.names = append(pkg.names, name)
		pkg.parts[fold(name)] = data
	}
	if pkg.contentTypes == nil {
		return nil, fmt.Errorf("%w: no %s", ErrNotPackage, contentTypesName)
	}
	if err := pkg.readContentTypes(pkg.contentTypes); err != nil {
		return nil, err
	}
	return pkg, nil
}

// readContentTypes reads the Default (by extension) and Override (by part
// name) content types.
func (p *Package) readContentTypes(content []byte) error {
	document := etree.NewDocument()
	if err := document.ReadFromBytes(content); err != nil || document.Root() == nil ||
		document.Root().Tag != "Types" || document.Root().NamespaceURI() != namespaceContentTypes {
		return fmt.Errorf("%w: unreadable %s", ErrNotPackage, contentTypesName)
	}
	for _, element := range document.Root().ChildElements() {
		contentType := element.SelectAttrValue("ContentType", "")
		switch element.Tag {
		case "Default":
			p.defaults[strings.ToLower(element.SelectAttrValue("Extension", ""))] = contentType
		case "Override":
			p.overrides[fold(element.SelectAttrValue("PartName", ""))] = contentType
		}
	}
	return nil
}

// Part returns a part's content.
func (p *Package) Part(name string) ([]byte, bool) {
	data, found := p.parts[fold(name)]
	return data, found
}

// ContentType is a part's content type: its Override, or the Default for
// its extension.
func (p *Package) ContentType(name string) string {
	if contentType, found := p.overrides[fold(name)]; found {
		return contentType
	}
	return p.defaults[strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))]
}

// Relationships reads the relationships of a source part; "/" is the
// package itself.
func (p *Package) relationships(source string) ([]Relationship, error) {
	content, found := p.Part(relationshipsPart(source))
	if !found {
		return nil, nil
	}
	return parseRelationships(content)
}

// relationshipsPart names the part holding a source's relationships:
// /word/_rels/document.xml.rels for /word/document.xml, /_rels/.rels for
// the package.
func relationshipsPart(source string) string {
	if source == "/" {
		return "/_rels/.rels"
	}
	return path.Join(path.Dir(source), "_rels", path.Base(source)+".rels")
}

// isRelationshipsPart reports a relationships part.
func isRelationshipsPart(name string) bool {
	return strings.HasSuffix(fold(name), ".rels") && path.Base(path.Dir(fold(name))) == "_rels"
}

// relationshipsSource is the part a relationships part belongs to: the
// inverse of relationshipsPart.
func relationshipsSource(name string) string {
	base := strings.TrimSuffix(path.Base(name), ".rels")
	if base == "" {
		return "/"
	}
	return path.Join(path.Dir(path.Dir(name)), base)
}

// targetPart is the part an internal relationship of source points at.
func (r Relationship) targetPart(source string) string {
	target, err := url.PathUnescape(r.Target)
	if err != nil {
		target = r.Target
	}
	if strings.HasPrefix(target, "/") {
		return path.Clean(target)
	}
	base := path.Dir(source)
	if source == "/" {
		base = "/"
	}
	return path.Join(base, target)
}

// parseRelationships reads a relationships part.
func parseRelationships(content []byte) ([]Relationship, error) {
	document := etree.NewDocument()
	if err := document.ReadFromBytes(content); err != nil || document.Root() == nil ||
		document.Root().Tag != "Relationships" || document.Root().NamespaceURI() != namespaceRelationships {
		return nil, fmt.Errorf("%w: unreadable relationships part", ErrNotPackage)
	}
	var relationships []Relationship
	for _, element := range document.Root().ChildElements() {
		if element.Tag != "Relationship" || element.NamespaceURI() != namespaceRelationships {
			continue
		}
		relationships = append(relationships, Relationship{
			ID:         element.SelectAttrValue("Id", ""),
			Type:       element.SelectAttrValue("Type", ""),
			Target:     element.SelectAttrValue("Target", ""),
			TargetMode: element.SelectAttrValue("TargetMode", ""),
		})
	}
	return relationships, nil
}

// fold is the form part names are compared in: unescaped, and without
// regard to ASCII case (§9.1.1.1), since producers escape differently.
func fold(name string) string {
	if unescaped, err := url.PathUnescape(name); err == nil {
		name = unescaped
	}
	return strings.ToLower(name)
}

// readEntry reads a ZIP entry whole, refusing one larger than partLimit.
func readEntry(entry *zip.File) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", entry.Name, err)
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, partLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", entry.Name, err)
	}
	if len(content) > partLimit {
		return nil, fmt.Errorf("%s is larger than %d bytes", entry.Name, partLimit)
	}
	return content, nil
}
