package application_test

// Signing a text, spreadsheet or presentation as its PDF, and writing that
// PDF beside it: the converter's PDF, kept aside and released after, is
// what is signed in PAdES; the document itself is never touched.

import (
	"context"
	"errors"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// fakeConverter "prints" a document to the PDF the store holds at pdf.
type fakeConverter struct {
	pdf       string
	err       error
	converted []string
	released  int
}

func (f *fakeConverter) ConvertToPDF(_ context.Context, document domain.Document) (domain.Document, func(), error) {
	if f.err != nil {
		return domain.Document{}, func() {}, f.err
	}
	f.converted = append(f.converted, document.Path())
	converted, _ := domain.OpenDocument(f.pdf)
	return converted, func() { f.released++ }, nil
}

func TestADocumentIsSignedAsItsPDF(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/scratch/contrato.pdf": []byte("%PDF-1.7 converted")})
	pades := &fakePades{}
	converter := &fakeConverter{pdf: "/scratch/contrato.pdf"}
	sign := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, fakeIdentity{}, &fakeCades{}, pades, &fakeXades{})
	document, _ := domain.OpenDocument("/docs/contrato.docx")

	artefact, err := application.NewSignAsPDF(converter, sign).Execute(context.Background(), application.Request{
		Document: document, Format: domain.Cades, Level: domain.BES, Signer: newSigner(t)})
	if err != nil {
		t.Fatal(err)
	}
	if artefact.Path != "/docs/contrato_signed.pdf" || artefact.Format != domain.Pades {
		t.Errorf("artefact %s in %s, want /docs/contrato_signed.pdf in PAdES", artefact.Path, artefact.Format)
	}
	if !pades.called || string(pades.request.Content) != "%PDF-1.7 converted" {
		t.Errorf("PAdES signed %q", pades.request.Content)
	}
	if len(converter.converted) != 1 || converter.converted[0] != "/docs/contrato.docx" || converter.released != 1 {
		t.Errorf("converted %v, released %d times", converter.converted, converter.released)
	}
	if _, written := store.written["/docs/contrato.docx"]; written {
		t.Error("the document itself was written")
	}

	// An output named is where the signed PDF goes.
	store = newFakeStore(map[string][]byte{"/scratch/contrato.pdf": []byte("%PDF-1.7 converted")})
	sign = application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, fakeIdentity{}, &fakeCades{}, &fakePades{}, &fakeXades{})
	named, err := application.NewSignAsPDF(converter, sign).Execute(context.Background(), application.Request{
		Document: document, Level: domain.BES, Signer: newSigner(t), OutputPath: "/out/firmado.pdf"})
	if err != nil || named.Path != "/out/firmado.pdf" {
		t.Errorf("named output: %v %s", err, named.Path)
	}
}

func TestOnlyAnOfficeDocumentIsSignedAsAPDF(t *testing.T) {
	converter := &fakeConverter{pdf: "/scratch/x.pdf"}
	sign := application.NewSignDocument(newFakeStore(nil), fakeClock{}, fakeIdentity{}, &fakeCades{}, &fakePades{}, &fakeXades{})
	for _, path := range []string{"/docs/acta.pdf", "/docs/foto.png", "/docs/acta.pdf.p7m"} {
		document, _ := domain.OpenDocument(path)
		if _, err := application.NewSignAsPDF(converter, sign).Execute(context.Background(), application.Request{
			Document: document, Level: domain.BES, Signer: newSigner(t)}); !errors.Is(err, domain.ErrNotConvertible) {
			t.Errorf("%s: %v", path, err)
		}
	}
	if len(converter.converted) != 0 {
		t.Errorf("converted %v", converter.converted)
	}
	failing := &fakeConverter{err: errors.New("no office suite")}
	document, _ := domain.OpenDocument("/docs/acta.odt")
	if _, err := application.NewSignAsPDF(failing, sign).Execute(context.Background(), application.Request{
		Document: document, Level: domain.BES, Signer: newSigner(t)}); err == nil || err.Error() != "no office suite" {
		t.Errorf("a failing conversion: %v", err)
	}
}

func TestADocumentIsConvertedBesideItself(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/scratch/hoja.pdf": []byte("%PDF hoja")})
	converter := &fakeConverter{pdf: "/scratch/hoja.pdf"}
	document, _ := domain.OpenDocument("/docs/hoja.xlsx")
	written, err := application.NewConvertDocument(converter, store).Execute(context.Background(), application.ConversionRequest{Document: document})
	if err != nil || written != "/docs/hoja.pdf" || string(store.written["/docs/hoja.pdf"]) != "%PDF hoja" || converter.released != 1 {
		t.Errorf("written %s: %v, %q, released %d", written, err, store.written["/docs/hoja.pdf"], converter.released)
	}

	// An existing PDF is kept unless the request says to replace it.
	store = newFakeStore(map[string][]byte{"/scratch/hoja.pdf": []byte("%PDF hoja"), "/docs/hoja.pdf": []byte("mine")})
	if _, err := application.NewConvertDocument(converter, store).Execute(context.Background(),
		application.ConversionRequest{Document: document}); !errors.Is(err, application.ErrWouldOverwrite) {
		t.Errorf("an existing PDF: %v", err)
	}
	if _, err := application.NewConvertDocument(converter, store).Execute(context.Background(),
		application.ConversionRequest{Document: document, Overwrite: true}); err != nil || string(store.written["/docs/hoja.pdf"]) != "%PDF hoja" {
		t.Errorf("replacing it: %v", err)
	}
	written, err = application.NewConvertDocument(converter, store).Execute(context.Background(),
		application.ConversionRequest{Document: document, OutputPath: "/out/hoja-impresa.pdf"})
	if err != nil || written != "/out/hoja-impresa.pdf" {
		t.Errorf("a named output: %v %s", err, written)
	}
	pdf, _ := domain.OpenDocument("/docs/acta.pdf")
	if _, err := application.NewConvertDocument(converter, store).Execute(context.Background(),
		application.ConversionRequest{Document: pdf}); !errors.Is(err, domain.ErrNotConvertible) {
		t.Errorf("a PDF: %v", err)
	}
}
