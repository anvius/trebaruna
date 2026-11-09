package integration_test

// Signing in a form's empty signature field: the signature goes in that
// field, the seal in its box, as an incremental update the earlier bytes and
// signatures survive. The output of the same code was also judged by hand:
// qpdf --check, poppler's pdfsig ("Signature is Valid", the field named)
// and mutool, on these forms and on one qpdf rewrote with object streams.

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/digitorus/pdf"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/pdffield"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

const formPage = "BT /F1 18 Tf 72 760 Td (Solicitud) Tj ET 300 100 200 60 re S 300 300 200 60 re S"

// formPDF writes a one-page form. Firma1 is a field merged with its widget;
// form.Firma2 a field with one widget kid, under a parent field. The form
// dictionary is an object of its own, or inside the catalogue (Firma1
// alone); the cross-reference section a table or a stream.
func formPDF(formInCatalogue, crossReferenceStream bool) []byte {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> /Annots [5 0 R 10 0 R] >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(formPage), formPage),
		"<< /FT /Sig /T (Firma1) /Type /Annot /Subtype /Widget /Rect [300 100 500 160] /P 3 0 R /F 4 >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		"<< /Fields [5 0 R 8 0 R] >>",
		"<< /T (form) /Kids [9 0 R] >>",
		"<< /FT /Sig /T (Firma2) /Parent 8 0 R /Kids [10 0 R] >>",
		"<< /Type /Annot /Subtype /Widget /Parent 9 0 R /Rect [300 300 500 360] /P 3 0 R /F 4 >>",
	}
	if formInCatalogue {
		objects[0] = "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] >> >>"
		objects[2] = strings.Replace(objects[2], " 10 0 R]", "]", 1)
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects)+2)
	for index, body := range objects {
		offsets[index+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", index+1, body)
	}
	identifier := "/ID [<0102030405060708090A0B0C0D0E0F10> <0102030405060708090A0B0C0D0E0F10>]"
	if !crossReferenceStream {
		start := out.Len()
		fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
		for _, offset := range offsets[1 : len(objects)+1] {
			fmt.Fprintf(&out, "%010d 00000 n \n", offset)
		}
		fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R %s >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, identifier, start)
		return out.Bytes()
	}
	streamID := len(objects) + 1
	offsets[streamID] = out.Len()
	var entries bytes.Buffer
	entries.Write([]byte{0, 0, 0, 0, 0, 0xFF, 0xFF})
	for _, offset := range offsets[1:] {
		entries.Write([]byte{1, byte(offset >> 24), byte(offset >> 16), byte(offset >> 8), byte(offset), 0, 0})
	}
	fmt.Fprintf(&out, "%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 2] /Root 1 0 R %s /Length %d >>\nstream\n",
		streamID, streamID+1, identifier, entries.Len())
	out.Write(entries.Bytes())
	fmt.Fprintf(&out, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", offsets[streamID])
	return out.Bytes()
}

func signField(t *testing.T, authority *localTSA, content []byte, request application.PadesRequest) []byte {
	t.Helper()
	request.Content = content
	request.SignedAt = timeNow()
	signed, err := infrastructure.NewPadesSigner(authority).SignPades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign in %q: %v", request.Field, err)
	}
	if !bytes.HasPrefix(signed, content) {
		t.Fatal("the update must leave the earlier bytes as they were")
	}
	return signed
}

// verifyPDF verifies with the local timestamp authority as an anchor.
func verifyPDF(t *testing.T, authority *localTSA, content []byte) []verificationdomain.SignerReport {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signed.pdf")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.ca)
	reports, err := verificationinfra.NewPDFVerifier().WithAnchorCertificates(roots, nil, []*x509.Certificate{authority.ca}).Extract(path)
	if err != nil {
		t.Fatal(err)
	}
	return reports
}

func emptyFieldNames(t *testing.T, content []byte) []string {
	t.Helper()
	fields, err := pdffield.EmptyFields(content)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, field := range fields {
		names = append(names, field.Name)
	}
	return names
}

func TestAFormIsSignedInItsFieldsOneAfterTheOther(t *testing.T) {
	fixture, authority := newFixture(t), newLocalTSA(t)
	form := formPDF(false, false)
	if names := emptyFieldNames(t, form); !slices.Equal(names, []string{"Firma1", "form.Firma2"}) {
		t.Fatalf("empty fields %v", names)
	}

	first := signField(t, authority, form, application.PadesRequest{Signer: pemSigner(t, fixture), Level: domain.T, Field: "form.Firma2",
		TimestampURL: "http://tsa.invalid"})
	if names := emptyFieldNames(t, first); !slices.Equal(names, []string{"Firma1"}) {
		t.Errorf("after the first signature, empty fields %v", names)
	}
	reports := verifyPDF(t, authority, first)
	if len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood || !reports[0].Timestamped {
		t.Fatalf("first signature: %+v", reports)
	}

	second := signField(t, authority, first, application.PadesRequest{Signer: pemSigner(t, fixture), Level: domain.BES, Field: "Firma1", Invisible: true})
	reports = verifyPDF(t, authority, second)
	if len(reports) != 2 {
		t.Fatalf("two signatures, got %d", len(reports))
	}
	for _, report := range reports {
		if report.Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %s %+v", report.FieldName, report.Integrity, report.Findings)
		}
	}
	if names := emptyFieldNames(t, second); len(names) != 0 {
		t.Errorf("empty fields left %v", names)
	}

	reader, err := pdf.NewReader(bytes.NewReader(second), int64(len(second)))
	if err != nil {
		t.Fatal(err)
	}
	fields := reader.Trailer().Key("Root").Key("AcroForm").Key("Fields")
	widget := fields.Index(1).Key("Kids").Index(0).Key("Kids").Index(0)
	if widget.Key("AP").Key("N").Kind() != pdf.Stream || !fields.Index(0).Key("AP").IsNull() {
		t.Error("the visible signature's widget has the seal, the invisible one none")
	}
	if fields.Index(1).Key("Kids").Index(0).Key("V").Key("SubFilter").Name() != "ETSI.CAdES.detached" ||
		reader.Trailer().Key("Root").Key("AcroForm").Key("SigFlags").Int64() != 3 {
		t.Error("the field's value is a PAdES signature and the form says it is signed")
	}
}

func TestAFormInTheCatalogueOrWithACrossReferenceStream(t *testing.T) {
	fixture, authority := newFixture(t), newLocalTSA(t)
	for name, form := range map[string][]byte{
		"form in the catalogue":    formPDF(true, false),
		"cross-reference stream":   formPDF(false, true),
		"both, a rubric in a seal": formPDF(true, true),
	} {
		request := application.PadesRequest{Signer: pemSigner(t, fixture), Level: domain.BES, Field: "Firma1"}
		if strings.Contains(name, "rubric") {
			request.Rubric = rubricOf(t, 120, 60, "png")
		}
		signed := signField(t, authority, form, request)
		reports := verifyPDF(t, authority, signed)
		if len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %+v", name, reports)
		}
		update := signed[len(form):]
		if stream := bytes.Contains(update, []byte("/Type /XRef")); stream != strings.Contains(name, "stream") && !strings.Contains(name, "both") {
			t.Errorf("%s: the update's cross-references are not of the file's kind", name)
		}
	}
}

func TestAFieldTheFormLacksIsRefusedWithTheOnesItHas(t *testing.T) {
	fixture := newFixture(t)
	_, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content: formPDF(false, false), Signer: pemSigner(t, fixture), Level: domain.BES, Field: "Firma3", SignedAt: timeNow(),
	})
	if err == nil || !strings.Contains(err.Error(), "Firma1, form.Firma2") {
		t.Errorf("%v", err)
	}
}

func TestAFieldTooSmallForTheIdentityAsksForAnInvisibleSignature(t *testing.T) {
	fixture := newFixture(t)
	form := bytes.Replace(formPDF(true, false), []byte("/Rect [300 100 500 160]"), []byte("/Rect [300 100 420 112]"), 1)
	_, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content: form, Signer: pemSigner(t, fixture), Level: domain.BES, Field: "Firma1", SignedAt: timeNow(),
	})
	if err == nil || !strings.Contains(err.Error(), "--invisible") {
		t.Errorf("%v", err)
	}
}

// TestTheRevocationEntryIsTheNewSignatures: in a form signed before, a
// B-LT signature's /VRI entry is keyed by its own value; the first field's
// was taken.
func TestTheRevocationEntryIsTheNewSignatures(t *testing.T) {
	fixture, authority := newFixture(t), newLocalTSA(t)
	_, signer := ltaFixture(t)
	first := signField(t, authority, formPDF(false, false), application.PadesRequest{Signer: pemSigner(t, fixture), Level: domain.BES, Field: "Firma1"})
	second, err := infrastructure.NewPadesSigner(authority).SignPades(context.Background(), application.PadesRequest{
		Content: first, Signer: signer, Level: domain.LT, Field: "form.Firma2", SignedAt: timeNow(),
		TimestampURL: authority.url(t), EmbedRevocation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := pdf.NewReader(bytes.NewReader(second), int64(len(second)))
	if err != nil {
		t.Fatal(err)
	}
	contents := reader.Trailer().Key("Root").Key("AcroForm").Key("Fields").Index(1).Key("Kids").Index(0).Key("V").Key("Contents").RawString()
	digest := sha1.Sum([]byte(contents))
	vri := reader.Trailer().Key("Root").Key("DSS").Key("VRI")
	if keys := vri.Keys(); len(keys) != 1 || keys[0] != strings.ToUpper(hex.EncodeToString(digest[:])) {
		t.Errorf("VRI keys %v, the new signature's %X", keys, digest)
	}
}
