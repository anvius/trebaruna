package domain

import (
	"errors"
	"path/filepath"
	"strings"
)

// ErrNotConvertible means a document an office suite does not turn into
// a PDF: a PDF already, a signature, an image, or anything unknown.
var ErrNotConvertible = errors.New("only a text, spreadsheet or presentation document is turned into a PDF")

// Convertible reports a document an office suite opens and can print to
// PDF: OpenDocument and Office Open XML files, the older Microsoft formats,
// RTF and plain text.
func (d Document) Convertible() bool {
	extension := d.Extension()
	if isOpenDocument(extension) || isOfficeOpenXML(extension) {
		return true
	}
	switch extension {
	case ".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot", ".pps", ".rtf", ".txt", ".csv":
		return true
	}
	return false
}

// AsPDF is the document its PDF conversion stands for: the same name in
// the same folder, ending in .pdf. contrato.docx becomes contrato.pdf.
func (d Document) AsPDF() Document {
	return Document{path: strings.TrimSuffix(d.path, filepath.Ext(d.path)) + ".pdf"}
}
