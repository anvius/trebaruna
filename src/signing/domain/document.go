package domain

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Document is a file that will be signed. The zero value is useless on
// purpose: a document always comes from a real path.
type Document struct {
	path string
}

// OpenDocument validates that the path looks like a signable file.
//
// It does not touch the filesystem: the infrastructure layer owns that
// decision, keeping this layer free of I/O.
func OpenDocument(path string) (Document, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return Document{}, fmt.Errorf("document path is empty")
	}
	if filepath.Clean(trimmed) == "." {
		return Document{}, fmt.Errorf("document path %q does not name a file", path)
	}
	return Document{path: trimmed}, nil
}

// Path returns the filesystem path of the document.
func (d Document) Path() string { return d.path }

// Name returns the base name, without directories.
func (d Document) Name() string { return filepath.Base(d.path) }

// Extension returns the lowercase extension including the dot.
func (d Document) Extension() string {
	return strings.ToLower(filepath.Ext(d.path))
}

// SignedName computes the output file name following the convention shared
// by the tools this replaces:
//
//   - CAdES appends the .p7m suffix to the whole original name,
//     so contratto.docx becomes contratto.docx.p7m.
//   - PAdES and XAdES insert _signed before the extension,
//     so contratto.pdf becomes contratto_signed.pdf.
func (d Document) SignedName(format Format) string {
	dir := filepath.Dir(d.path)
	base := filepath.Base(d.path)

	if format == Cades {
		return filepath.Join(dir, base+format.Extension())
	}

	stem := strings.TrimSuffix(base, filepath.Ext(base))
	extension := format.Extension()
	if format.IsOfficePackage() {
		// An office document stays one, signed inside.
		extension = filepath.Ext(base)
	}
	return filepath.Join(dir, stem+"_signed"+extension)
}

// AddedSignatureName is where an envelope goes after a signature is added
// to it: the same name with a marker before the last extension, so the
// original envelope is never overwritten (contratto.pdf.p7m becomes
// contratto.pdf_cosigned.p7m).
func (d Document) AddedSignatureName(marker string) string {
	extension := filepath.Ext(d.path)
	return strings.TrimSuffix(d.path, extension) + "_" + marker + extension
}

// DetachedSignatureName is where a detached signature goes, next to the
// document it signs: its name plus .p7s for CAdES, plus .xsig for XAdES (the
// suffix AutoFirma gives XML signatures).
func (d Document) DetachedSignatureName(format Format) string {
	if format.IsXML() {
		return d.path + ".xsig"
	}
	return d.path + ".p7s"
}

// ContainerName is where a container holding the document goes: its name
// plus .asics or .asice, next to it.
func (d Document) ContainerName(container Container) string {
	return d.path + container.Extension()
}

// Supports reports whether the format makes sense for this document.
func (d Document) Supports(format Format) bool {
	switch format {
	case Pades:
		return d.Extension() == ".pdf"
	case Xades, Xmldsig:
		return d.Extension() == ".xml" || d.Extension() == ".xsd" || d.Extension() == ".svg"
	case Odf:
		return isOpenDocument(d.Extension())
	case Ooxml:
		return isOfficeOpenXML(d.Extension())
	case Cades:
		return true
	}
	return false
}

// InferFormat picks the format the document's suffix implies.
//
// The default used to be PAdES regardless of the file, so `sign doc.xml` failed
// with "cannot hold a pades signature" instead of doing the obvious thing. A
// caller that passes --format still wins; this only decides what happens when
// nobody said.
//
// The choice is by extension, not by content: the extension is what the user
// chose when naming the file, and reading the bytes to guess would be a surprise
// on a large or unusual document.
func (d Document) InferFormat() Format {
	switch d.Extension() {
	case ".pdf":
		return Pades
	case ".xml", ".xsd", ".svg":
		return Xades
	}
	if isOpenDocument(d.Extension()) {
		return Odf
	}
	if isOfficeOpenXML(d.Extension()) {
		return Ooxml
	}
	// Anything else is signed as a CMS container, which works for any bytes.
	return Cades
}

// isOfficeOpenXML reports an Office Open XML suffix: Word, Excel and
// PowerPoint documents, macro-enabled ones, templates and shows.
func isOfficeOpenXML(extension string) bool {
	switch extension {
	case ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
		".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm":
		return true
	}
	return false
}

// isOpenDocument reports an OpenDocument suffix: texts, spreadsheets,
// presentations, drawings, formulas and their templates.
func isOpenDocument(extension string) bool {
	switch extension {
	case ".odt", ".ods", ".odp", ".odg", ".odf", ".odm", ".ott", ".ots", ".otp", ".otg":
		return true
	}
	return false
}
