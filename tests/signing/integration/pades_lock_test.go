package integration_test

// A signature field's lock (ISO 32000-1, 12.7.4.5): signing the field
// records it as a FieldMDP reference (12.8.2.4), and later signatures
// respect it: no signature after one that allows no change (PDF 2.0's P
// 1), and no signature in a field an earlier signature locked.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
