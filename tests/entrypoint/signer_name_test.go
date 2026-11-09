package cli_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeOnePagePDF writes a minimal PDF with a real cross-reference table.
func writeOnePagePDF(t *testing.T) string {
	t.Helper()
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
	}
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

	path := filepath.Join(t.TempDir(), "contratto.pdf")
	if err := os.WriteFile(path, []byte(pdf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestASignatureCarriesTheHolderName: the signature dictionary's /Name and the
// receipt said "signer" (and "handler", "api" from the other entry points),
// where every PDF reader expects the person who signed.
func TestASignatureCarriesTheHolderName(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	document := writeOnePagePDF(t)
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")

	stdout, stderr, code := run("sign", document, "--p12", key, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var receipt struct {
		Path   string `json:"path"`
		Signer string `json:"signer"`
	}
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Signer != "MARIO ROSSI" {
		t.Errorf("receipt signer = %q", receipt.Signer)
	}
	signed, err := os.ReadFile(receipt.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signed), "/Name (MARIO ROSSI)") {
		t.Error("the PDF signature dictionary does not name the holder")
	}
}

func TestAnExplicitNameStillWins(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")

	stdout, stderr, code := run("sign", writeOnePagePDF(t), "--p12", key, "--name", "Studio Rossi", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, `"signer": "Studio Rossi"`) {
		t.Errorf("stdout = %s", stdout)
	}
}
