package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/tests/support/tsa"
)

// formDocument writes a one-page PDF with an empty signature field Firma1;
// catalogue adds entries to the catalogue, extra objects after the others
// (numbered from 7).
func formDocument(t *testing.T, name, catalogue string, extra ...string) string {
	t.Helper()
	page := "BT /F1 18 Tf 72 760 Td (Solicitud) Tj ET 300 100 200 60 re S"
	objects := append([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] >> " + catalogue + " >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> /Annots [5 0 R] >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(page), page),
		"<< /FT /Sig /T (Firma1) /Type /Annot /Subtype /Widget /Rect [300 100 500 160] /P 3 0 R /F 4 >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}, extra...)
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
	return writeDocument(t, name, out.String())
}

// TestACertifiedPDFThatForbidsChangesIsNotSigned: a certification signature
// whose DocMDP permissions are 1 forbids any change, a signature included;
// 2 allows filling in forms and signing.
func TestACertifiedPDFThatForbidsChangesIsNotSigned(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	certification := func(permissions int) string {
		return fmt.Sprintf("<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Reference [<< /Type /SigRef "+
			"/TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P %d /V /1.2 >> >>] >>", permissions)
	}
	forbidding := formDocument(t, "certificado.pdf", "/Perms << /DocMDP 7 0 R >>", certification(1))
	// Invisible, the PDF library writes the signature; in a field, trebaruna.
	for _, how := range [][]string{{"--invisible"}, {"--field", "Firma1"}} {
		_, stderr, code := run(append([]string{"sign", forbidding, "--p12", key}, how...)...)
		if code == 0 || !strings.Contains(stderr, "certified it against any change") {
			t.Errorf("certified against changes, %v: exit %d, %q", how, code, stderr)
		}
	}
	allowing := formDocument(t, "formulario.pdf", "/Perms << /DocMDP 7 0 R >>", certification(2))
	if _, stderr, code := run("sign", allowing, "--p12", key, "--field", "Firma1"); code != 0 {
		t.Errorf("certified allowing forms: exit %d, %s", code, stderr)
	}
}

// TestTheFieldsCommandListsTheEmptySignatureFields: by name, page and box,
// for a person and as JSON; a signed field is no longer listed.
func TestTheFieldsCommandListsTheEmptySignatureFields(t *testing.T) {
	document := formDocument(t, "solicitud.pdf", "")
	stdout, stderr, code := run("fields", document)
	if code != 0 || strings.TrimSpace(stdout) != "Firma1  page 1  box 300,100,500,160  (200x60 pt)" {
		t.Errorf("exit %d: %q %s", code, stdout, stderr)
	}
	stdout, _, _ = run("fields", document, "--json")
	var listed struct {
		Fields []struct {
			Name string    `json:"name"`
			Page int       `json:"page"`
			Box  []float64 `json:"box"`
		} `json:"fields"`
	}
	if err := json.Unmarshal([]byte(stdout), &listed); err != nil || len(listed.Fields) != 1 || listed.Fields[0].Name != "Firma1" ||
		listed.Fields[0].Page != 1 || len(listed.Fields[0].Box) != 4 || listed.Fields[0].Box[2] != 500 {
		t.Errorf("JSON: %s (%v)", stdout, err)
	}

	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	if _, stderr, code := run("sign", document, "--p12", key, "--field", "Firma1"); code != 0 {
		t.Fatalf("sign the field: exit %d: %s", code, stderr)
	}
	if stdout, _, code := run("fields", filepath.Join(filepath.Dir(document), "solicitud_signed.pdf")); code != 0 ||
		strings.TrimSpace(stdout) != "no empty signature field" {
		t.Errorf("after signing: exit %d %q", code, stdout)
	}
	if _, _, code := run("fields", writeDocument(t, "acta.txt", "acta\n")); code == 0 {
		t.Error("a file that is no PDF has no fields to list")
	}
}

// TestATimestampTravelsWithItsDocumentInAnASiC: timestamp --asic writes the
// document and META-INF/timestamp.tst; verify reads the token over it.
func TestATimestampTravelsWithItsDocumentInAnASiC(t *testing.T) {
	authority := tsa.New(t).URL(t)
	document := writeDocument(t, "verbale.pdf", "%PDF-1.4 verbale di assemblea\n")
	if _, stderr, code := run("timestamp", document, "--tsa", authority, "--asic"); code != 0 {
		t.Fatalf("timestamp --asic: exit %d: %s", code, stderr)
	}
	names, method := containerEntries(t, document+".asics")
	if strings.Join(names, " ") != "mimetype verbale.pdf META-INF/timestamp.tst" || method != 0 {
		t.Errorf("container: %v (mimetype method %d)", names, method)
	}
	result := verifyJSON(t, document+".asics")
	if result.Signers[0].Field != "META-INF/timestamp.tst" || result.Signers[0].Integrity != "good" {
		t.Errorf("the token over the document: %+v", result.Signers[0])
	}
	changed := rewriteEntry(t, document+".asics", "verbale.pdf", []byte("%PDF-1.4 otro verbale\n"))
	if result := verifyJSON(t, changed); result.Verdict != "broken" {
		t.Errorf("a changed document: %s", result.Verdict)
	}
	if _, stderr, code := run("timestamp", document, "--tsa", authority, "--asic", "--tsd"); code == 0 || !strings.Contains(stderr, "exclude each other") {
		t.Errorf("--asic with --tsd: exit %d, %q", code, stderr)
	}
}
