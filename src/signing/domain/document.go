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
	return filepath.Join(dir, stem+"_signed"+format.Extension())
}

// Supports reports whether the format makes sense for this document.
func (d Document) Supports(format Format) bool {
	switch format {
	case Pades:
		return d.Extension() == ".pdf"
	case Xades:
		return d.Extension() == ".xml" || d.Extension() == ".xsd" || d.Extension() == ".svg"
	case Cades:
		return true
	}
	return false
}
