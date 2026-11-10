package integration_test

// A signature field's lock (ISO 32000-1, 12.7.4.5): signing the field
// records it as a FieldMDP reference (12.8.2.4), and later signatures
// respect it: no signature after one that allows no change (PDF 2.0's P
// 1), and no signature in a field an earlier signature locked.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/digitorus/pdf"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/pdffield"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// signatureReference is the first signature reference of the field's
// value, and the catalogue it should point at.
func signatureReference(t *testing.T, content []byte, field string) (pdf.Value, pdf.Ptr) {
	t.Helper()
	reader, err := pdf.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	fields := reader.Trailer().Key("Root").Key("AcroForm").Key("Fields")
	for index := 0; index < fields.Len(); index++ {
		if fields.Index(index).Key("T").Text() == field {
			return fields.Index(index).Key("V").Key("Reference").Index(0), reader.Trailer().Key("Root").GetPtr()
		}
	}
	t.Fatalf("no field %s", field)
	return pdf.Value{}, pdf.Ptr{}
}

func TestASignedFieldRecordsItsLock(t *testing.T) {
	fixture, authority := newFixture(t), newLocalTSA(t)
	form := formPDFWith("/Lock << /Type /SigFieldLock /Action /Include /Fields [(form.Firma2)] >>", false, false)
	signed := signField(t, authority, form, application.PadesRequest{Signer: pemSigner(t, fixture), Level: domain.BES, Field: "Firma1", Invisible: true})

	lock, catalogue := signatureReference(t, signed, "Firma1")
	parameters := lock.Key("TransformParams")
	if lock.Key("Type").Name() != "SigRef" || lock.Key("TransformMethod").Name() != "FieldMDP" || lock.Key("Data").GetPtr() != catalogue ||
		parameters.Key("Type").Name() != "TransformParams" || parameters.Key("Action").Name() != "Include" ||
		parameters.Key("Fields").Len() != 1 || parameters.Key("Fields").Index(0).Text() != "form.Firma2" || parameters.Key("V").Name() != "1.2" {
		t.Errorf("the FieldMDP reference: %v", lock)
	}
	if reports := verifyPDF(t, authority, signed); len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood {
		t.Errorf("%+v", reports)
	}
	if _, err := exec.LookPath("pdfsig"); err == nil {
		path := filepath.Join(t.TempDir(), "locked.pdf")
		os.WriteFile(path, signed, 0o600)
		if output, err := exec.Command("pdfsig", path).CombinedOutput(); err != nil || !strings.Contains(string(output), "Signature Validation: Signature is Valid.") {
			t.Errorf("pdfsig: %v\n%s", err, output)
		}
	}
	if _, err := exec.LookPath("qpdf"); err == nil {
		path := filepath.Join(t.TempDir(), "locked.pdf")
		os.WriteFile(path, signed, 0o600)
		if output, err := exec.Command("qpdf", "--check", path).CombinedOutput(); err != nil || !strings.Contains(string(output), "No syntax or stream encoding errors found") {
			t.Errorf("qpdf: %v\n%s", err, output)
		}
	}

	// The field it locked is not signed after it.
	_, err := infrastructure.NewPadesSigner(authority).SignPades(context.Background(), application.PadesRequest{Content: signed,
		Signer: pemSigner(t, fixture), Level: domain.BES, Field: "form.Firma2", Invisible: true, SignedAt: timeNow()})
	if err == nil || !strings.Contains(err.Error(), `locked the field "form.Firma2"`) {
		t.Errorf("signing the locked field: %v", err)
	}
}

func TestLaterSignaturesRespectALock(t *testing.T) {
	fixture, authority := newFixture(t), newLocalTSA(t)
	sign := func(content []byte, field string) ([]byte, error) {
		return infrastructure.NewPadesSigner(authority).SignPades(context.Background(), application.PadesRequest{Content: content,
			Signer: pemSigner(t, fixture), Level: domain.BES, Field: field, Invisible: true, SignedAt: timeNow()})
	}
	for name, check := range map[string]struct {
		lock, refusal string
	}{
		"excluding the next field": {"/Lock << /Action /Exclude /Fields [(form.Firma2)] >>", ""},
		"including another field":  {"/Lock << /Action /Include /Fields [(Nombre)] >>", ""},
		"including the next field": {"/Lock << /Action /Include /Fields [(Nombre) (form.Firma2)] >>", `locked the field "form.Firma2"`},
		"every field":              {"/Lock << /Action /All >>", `locked the field "form.Firma2"`},
		"including its parent":     {"/Lock << /Action /Include /Fields [(form)] >>", `locked the field "form.Firma2"`},
		"no change at all":         {"/Lock << /Action /Include /Fields [(Nombre)] /P 1 >>", "against any change"},
		"a lock with no action":    {"/Lock << /Fields [(form.Firma2)] >>", ""},
	} {
		first, err := sign(formPDFWith(check.lock, false, false), "Firma1")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = sign(first, "form.Firma2")
		if check.refusal == "" && err != nil || check.refusal != "" && (err == nil || !strings.Contains(err.Error(), check.refusal)) {
			t.Errorf("%s: the next field: %v", name, err)
		}
		// A new, invisible signature: only a lock against any change forbids it.
		_, err = sign(first, "")
		if (check.refusal == "against any change") != (err != nil) {
			t.Errorf("%s: a new signature: %v", name, err)
		}
	}
	// pdffield refuses on its own too, for a new field.
	locked, err := sign(formPDFWith("/Lock << /Action /All /P 1 >>", false, false), "Firma1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pdffield.SignNew(locked, nil, pdffield.Signature{SignedAt: timeNow(), Envelope: func([]byte) ([]byte, error) { return []byte{0x30}, nil }})
	if err == nil || !strings.Contains(err.Error(), "against any change") {
		t.Errorf("a new field in a document locked against any change: %v", err)
	}

	unlocked, _ := sign(formPDFWith("/Lock << /Fields [(form.Firma2)] >>", false, false), "Firma1")
	if lock, _ := signatureReference(t, unlocked, "Firma1"); !lock.IsNull() {
		t.Errorf("a lock with no action is no FieldMDP reference: %v", lock)
	}
}

// lockForm is a form whose signature field Firma1 carries the lock given,
// with text fields around it: address.street, which inherits Multiline
// (4096) from its parent, name, with no flags, and notes, read-only
// already; inline adds fields written inside the field list.
func lockForm(lock string, inline ...string) []byte {
	widget := " /Type /Annot /Subtype /Widget /P 3 0 R /Rect [50 %d 250 %d]"
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> /Annots [5 0 R 9 0 R 10 0 R 11 0 R] >>",
		"<< /Length 3 >>\nstream\nq Q\nendstream",
		"<< /FT /Sig /T (Firma1) " + lock + " /Type /Annot /Subtype /Widget /Rect [300 100 500 160] /P 3 0 R /F 4 >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		"<< /Fields [5 0 R 8 0 R 10 0 R 11 0 R" + strings.Join(append([]string{""}, inline...), " ") + "] >>",
		"<< /T (address) /FT /Tx /Ff 4096 /Kids [9 0 R] >>",
		"<< /T (street) /Parent 8 0 R" + fmt.Sprintf(widget, 700, 720) + " >>",
		"<< /T (name) /FT /Tx" + fmt.Sprintf(widget, 650, 670) + " >>",
		"<< /T (notes) /FT /Tx /Ff 1" + fmt.Sprintf(widget, 600, 620) + " >>",
	}
	return pdfOf(objects)
}

// pdfOf writes the objects, numbered from 1 with the catalogue first, with
// a cross-reference table.
func pdfOf(objects []string) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for index, body := range objects {
		offsets[index] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", index+1, body)
	}
	start := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /ID [<0102030405060708090A0B0C0D0E0F10> <0102030405060708090A0B0C0D0E0F10>] >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, start)
	return out.Bytes()
}

// ownFlags are the Ff each terminal field carries itself, by qualified
// name; -1 when it carries none.
func ownFlags(t *testing.T, content []byte) map[string]int64 {
	t.Helper()
	reader, err := pdf.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]int64{}
	var visit func(fields pdf.Value, prefix string)
	visit = func(fields pdf.Value, prefix string) {
		for index := 0; index < fields.Len(); index++ {
			field := fields.Index(index)
			name := strings.TrimPrefix(prefix+"."+field.Key("T").Text(), ".")
			if kids := field.Key("Kids"); kids.Len() > 0 {
				visit(kids, name)
				continue
			}
			flags[name] = -1
			if own := field.Key("Ff"); !own.IsNull() {
				flags[name] = own.Int64()
			}
		}
	}
	visit(reader.Trailer().Key("Root").Key("AcroForm").Key("Fields"), "")
	return flags
}

// TestTheFieldsALockCoversBecomeReadOnly: signing the field marks the
// fields its lock covers read-only, each keeping the flags it had or
// inherited; a field already read-only is not written again, and the
// signed field and the fields the lock leaves out are untouched.
func TestTheFieldsALockCoversBecomeReadOnly(t *testing.T) {
	fixture, authority := newFixture(t), newLocalTSA(t)
	for lock, want := range map[string]map[string]int64{
		"/Lock << /Action /Include /Fields [(address)] >>": {"Firma1": -1, "address.street": 4097, "name": -1, "notes": 1},
		"/Lock << /Action /Exclude /Fields [(name)] >>":    {"Firma1": -1, "address.street": 4097, "name": -1, "notes": 1},
		"/Lock << /Action /All >>":                         {"Firma1": -1, "address.street": 4097, "name": 1, "notes": 1},
		"/Lock << /Fields [(name)] >>":                     {"Firma1": -1, "address.street": -1, "name": -1, "notes": 1},
	} {
		signed := signField(t, authority, lockForm(lock), application.PadesRequest{Signer: pemSigner(t, fixture), Level: domain.BES, Field: "Firma1", Invisible: true})
		got := ownFlags(t, signed)
		for field, flags := range want {
			if got[field] != flags {
				t.Errorf("%s: %s carries Ff %d, want %d", lock, field, got[field], flags)
			}
		}
		if rewritten := bytes.Count(signed, []byte("\n11 0 obj")); rewritten != 1 {
			t.Errorf("%s: the read-only field was written %d times", lock, rewritten)
		}
		if reports := verifyPDF(t, authority, signed); len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %+v", lock, reports)
		}
		if lock != "/Lock << /Action /All >>" {
			continue
		}
		path := filepath.Join(t.TempDir(), "read-only.pdf")
		os.WriteFile(path, signed, 0o600)
		if _, err := exec.LookPath("qpdf"); err == nil {
			if output, err := exec.Command("qpdf", "--check", path).CombinedOutput(); err != nil || !strings.Contains(string(output), "No syntax or stream encoding errors found") {
				t.Errorf("qpdf: %v\n%s", err, output)
			}
		}
		if _, err := exec.LookPath("pdfsig"); err == nil {
			if output, err := exec.Command("pdfsig", path).CombinedOutput(); err != nil || !strings.Contains(string(output), "Signature Validation: Signature is Valid.") {
				t.Errorf("pdfsig: %v\n%s", err, output)
			}
		}
	}
}

// TestAFieldWrittenInsideAnotherObjectIsNotRewritten: ISO 32000-1 has the
// field list hold references, and the PDF reader gives a field written
// inside another object that object's number. A locked field written so
// is left as it is, the form object it sits in kept whole; a signature
// field written so, or whose widget is, is refused rather than signed into
// the wrong object.
func TestAFieldWrittenInsideAnotherObjectIsNotRewritten(t *testing.T) {
	fixture, authority := newFixture(t), newLocalTSA(t)
	sign := func(content []byte, field string) ([]byte, error) {
		return infrastructure.NewPadesSigner(authority).SignPades(context.Background(), application.PadesRequest{Content: content,
			Signer: pemSigner(t, fixture), Level: domain.BES, Field: field, Invisible: true, SignedAt: timeNow()})
	}
	form := lockForm("/Lock << /Action /All >>", "<< /T (inline) /FT /Tx >>")
	signed, err := sign(form, "Firma1")
	if err != nil {
		t.Fatal(err)
	}
	if flags := ownFlags(t, signed); flags["inline"] != -1 || flags["name"] != 1 {
		t.Errorf("flags %v", flags)
	}
	// The form object is written once, for its SigFlags, not also as the field.
	if written := regexp.MustCompile(`(?m)^7 0 obj`).FindAll(signed[len(form):], -1); len(written) != 1 {
		t.Errorf("the form object was written %d times", len(written))
	}

	inlineField := lockForm("", "<< /T (Inline) /FT /Sig /Type /Annot /Subtype /Widget /Rect [300 300 500 360] /P 3 0 R >>")
	if _, err := sign(inlineField, "Inline"); err == nil || !strings.Contains(err.Error(), "written inside another object") {
		t.Errorf("a signature field inside the field list: %v", err)
	}
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << >> >>",
		"<< /Length 3 >>\nstream\nq Q\nendstream",
		"<< /FT /Sig /T (Kid) /Kids [<< /Type /Annot /Subtype /Widget /Rect [300 300 500 360] /P 3 0 R >>] >>",
	}
	if _, err := sign(pdfOf(objects), "Kid"); err == nil || !strings.Contains(err.Error(), "written inside another object") {
		t.Errorf("a signature field whose widget is inside it: %v", err)
	}
}
