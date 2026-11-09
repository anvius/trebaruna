package cli_test

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// writeSizedPDF writes a one-page PDF whose MediaBox sits on the page or,
// when inherited, on the page tree node above it.
func writeSizedPDF(t *testing.T, box string, inherited bool) string {
	t.Helper()
	pages := "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
	page := "<< /Type /Page /Parent 2 0 R /MediaBox " + box + " >>"
	if inherited {
		pages = "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox " + box + " >>"
		page = "<< /Type /Page /Parent 2 0 R >>"
	}
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", pages, page}
	var pdf strings.Builder
	pdf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for index, object := range objects {
		offsets[index] = pdf.Len()
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", index+1, object)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	path := filepath.Join(t.TempDir(), "documento.pdf")
	if err := os.WriteFile(path, []byte(pdf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var widgetRect = regexp.MustCompile(`/Rect \[\s*([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s*\]`)

func signedRect(t *testing.T, document string, extra ...string) []string {
	t.Helper()
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	arguments := append([]string{"sign", document, "--p12", key, "--json"}, extra...)
	if _, stderr, code := run(arguments...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	signed, err := os.ReadFile(strings.TrimSuffix(document, ".pdf") + "_signed.pdf")
	if err != nil {
		t.Fatal(err)
	}
	match := widgetRect.FindStringSubmatch(string(signed))
	if match == nil {
		t.Fatal("no signature widget in the output")
	}
	return match[1:]
}

func TestTheDefaultSealFollowsThePageSize(t *testing.T) {
	cases := []struct {
		name      string
		box       string
		inherited bool
		want      []string
	}{
		{"letter", "[0 0 612 792]", false, []string{"530.000000", "18.000000", "594.000000", "66.000000"}},
		{"landscape inherited from the page tree", "[0 0 842 595]", true, []string{"760.000000", "18.000000", "824.000000", "66.000000"}},
	}
	for _, testCase := range cases {
		got := signedRect(t, writeSizedPDF(t, testCase.box, testCase.inherited))
		if !sameNumbers(got, testCase.want) {
			t.Errorf("%s: seal at %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

func TestAnInvisibleSignatureHasAnEmptyWidget(t *testing.T) {
	got := signedRect(t, writeSizedPDF(t, "[0 0 595 842]", false), "--invisible")
	for _, coordinate := range got {
		if coordinate != "0" {
			t.Fatalf("widget = %v, want [0 0 0 0]", got)
		}
	}
}

func TestInvisibleAndABoxExcludeEachOther(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	if _, _, code := run("sign", writeSizedPDF(t, "[0 0 595 842]", false), "--p12", key, "--invisible", "--box", "10,10,90,70"); code != 2 {
		t.Errorf("exit %d, want 2 (usage)", code)
	}
}

// writeRubric writes a 300x100 transparent PNG.
func writeRubric(t *testing.T) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, image.NewNRGBA(image.Rect(0, 0, 300, 100))); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "firma.png")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestARubricWidensTheDefaultSeal: 160 pt in the corner, the image inside.
func TestARubricWidensTheDefaultSeal(t *testing.T) {
	document := writeSizedPDF(t, "[0 0 612 792]", false)
	got := signedRect(t, document, "--rubric", writeRubric(t))
	if !sameNumbers(got, []string{"434", "18", "594", "66"}) {
		t.Errorf("seal at %v, want 160 pt wide in the corner", got)
	}
	signed, _ := os.ReadFile(strings.TrimSuffix(document, ".pdf") + "_signed.pdf")
	if !strings.Contains(string(signed), "/Subtype /Image") {
		t.Error("no image in the seal")
	}
}

// TestARubricNeedsAVisibleSealAndAnImage.
func TestARubricNeedsAVisibleSealAndAnImage(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeSizedPDF(t, "[0 0 595 842]", false)
	if _, stderr, code := run("sign", document, "--p12", key, "--rubric", document); code != 2 || !strings.Contains(stderr, "PNG or JPEG") {
		t.Errorf("a PDF as rubric: exit %d, %s", code, stderr)
	}
	if _, stderr, code := run("sign", document, "--p12", key, "--invisible", "--rubric", writeRubric(t)); code == 0 || !strings.Contains(stderr, "visible seal") {
		t.Errorf("an invisible signature with a rubric: exit %d, %s", code, stderr)
	}
}

// sameNumbers compares coordinates by value: 530 and 530.000000 are one.
func sameNumbers(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		a, errA := strconv.ParseFloat(got[index], 64)
		b, errB := strconv.ParseFloat(want[index], 64)
		if errA != nil || errB != nil || a != b {
			return false
		}
	}
	return true
}
