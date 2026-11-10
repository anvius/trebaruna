package application

import (
	"context"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// SignAsPDF signs a text, spreadsheet or presentation document as a PDF:
// the office suite prints it to PDF, kept aside, and that PDF is signed in
// PAdES, written beside the document as <name>_signed.pdf unless the
// request names the output. What is signed is the PDF, which is what the
// person can open and read; the document itself is not touched.
type SignAsPDF struct {
	converter PDFConverter
	sign      *SignDocument
}

// NewSignAsPDF wires the use case over the signing one.
func NewSignAsPDF(converter PDFConverter, sign *SignDocument) *SignAsPDF {
	return &SignAsPDF{converter: converter, sign: sign}
}

// Execute converts and signs.
func (u *SignAsPDF) Execute(ctx context.Context, request Request) (Artefact, error) {
	if !request.Document.Convertible() {
		return Artefact{}, fmt.Errorf("%w: %s", domain.ErrNotConvertible, request.Document.Name())
	}
	if request.OutputPath == "" {
		request.OutputPath = request.Document.SignedName(domain.Pades)
	}
	converted, release, err := u.converter.ConvertToPDF(ctx, request.Document)
	if err != nil {
		return Artefact{}, err
	}
	defer release()
	request.Document, request.Format = converted, domain.Pades
	return u.sign.Execute(ctx, request)
}
