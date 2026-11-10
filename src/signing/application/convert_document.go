package application

import (
	"context"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// ConversionRequest names a document to turn into a PDF and where the PDF
// goes: beside it, under the same name ending in .pdf, unless OutputPath
// says otherwise. An existing file is replaced only with Overwrite.
type ConversionRequest struct {
	Document   domain.Document
	OutputPath string
	Overwrite  bool
}

// ConvertDocument turns a text, spreadsheet or presentation document into
// a PDF, as an office suite prints it, and writes it where the request
// says.
type ConvertDocument struct {
	converter PDFConverter
	files     FileStore
}

// NewConvertDocument wires the use case.
func NewConvertDocument(converter PDFConverter, files FileStore) *ConvertDocument {
	return &ConvertDocument{converter: converter, files: files}
}

// Execute converts the document and returns where the PDF was written.
func (u *ConvertDocument) Execute(ctx context.Context, request ConversionRequest) (string, error) {
	if !request.Document.Convertible() {
		return "", fmt.Errorf("%w: %s", domain.ErrNotConvertible, request.Document.Name())
	}
	output := request.OutputPath
	if output == "" {
		output = request.Document.AsPDF().Path()
	}
	if !request.Overwrite && u.files.Exists(output) {
		return "", fmt.Errorf("%w: %s (choose another --out, or --force to replace it)", ErrWouldOverwrite, output)
	}
	converted, release, err := u.converter.ConvertToPDF(ctx, request.Document)
	if err != nil {
		return "", err
	}
	defer release()
	content, err := u.files.Read(converted.Path())
	if err != nil {
		return "", err
	}
	if err := u.files.Write(output, content); err != nil {
		return "", err
	}
	return output, nil
}
