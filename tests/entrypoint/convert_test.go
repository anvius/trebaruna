package cli_test

// A text, spreadsheet or presentation signed as its PDF, which LibreOffice
// prints: `sign --to-pdf` writes <document>_signed.pdf beside the document
// and nothing else, and `convert` writes the PDF itself, never over an
// existing file unless asked.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// officeDocument is an RTF document LibreOffice reads.
func officeDocument(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("soffice"); err != nil {
		t.Skip("LibreOffice (soffice) is not installed")
	}
	return writeDocument(t, "contrato.rtf", `{\rtf1\ansi\deff0{\fonttbl{\f0 Liberation Serif;}}\f0\fs24 Contrato de arrendamiento: el arrendatario acepta.\par}`)
}

func TestADocumentIsSignedAsItsPDF(t *testing.T) {
	document := officeDocument(t)
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")

	stdout, stderr, code := run("sign", document, "--to-pdf", "--p12", key, "--json")
	signed := filepath.Join(filepath.Dir(document), "contrato_signed.pdf")
	if code != 0 || !strings.Contains(stdout, `"path": "`+signed+`"`) || !strings.Contains(stdout, `"format": "pades"`) {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}
	entries, _ := os.ReadDir(filepath.Dir(document))
	if len(entries) != 2 {
		t.Errorf("the folder holds %d files, want the document and its signed PDF", len(entries))
	}
	if result := verifyJSON(t, signed); result.Signers[0].Integrity != "good" {
		t.Errorf("integrity %s", result.Signers[0].Integrity)
	}
	if _, err := exec.LookPath("pdftotext"); err == nil {
		if text, _ := exec.Command("pdftotext", signed, "-").Output(); !strings.Contains(string(text), "el arrendatario acepta") {
			t.Errorf("the signed PDF reads %q", text)
		}
	}
	if _, err := exec.LookPath("pdfsig"); err == nil {
		if output, _ := exec.Command("pdfsig", signed).CombinedOutput(); !strings.Contains(string(output), "Signature is Valid") {
			t.Errorf("pdfsig: %s", output)
		}
	}

	for _, refused := range [][]string{{"--detached"}, {"--format", "cades"}, {"--asic", "s"}} {
		if _, stderr, code := run(append([]string{"sign", document, "--to-pdf", "--p12", key}, refused...)...); code == 0 ||
			!strings.Contains(stderr, "--to-pdf") {
			t.Errorf("--to-pdf with %v: exit %d, %s", refused, code, stderr)
		}
	}
	pdf := writeDocument(t, "acta.pdf", "%PDF-1.7\n")
	if _, stderr, code := run("sign", pdf, "--to-pdf", "--p12", key); code == 0 || !strings.Contains(stderr, "turned into a PDF") {
		t.Errorf("a PDF with --to-pdf: exit %d, %s", code, stderr)
	}
}

func TestADocumentIsConvertedToAPDF(t *testing.T) {
	document := officeDocument(t)
	pdf := filepath.Join(filepath.Dir(document), "contrato.pdf")
	stdout, stderr, code := run("convert", document)
	if code != 0 || !strings.Contains(stdout, pdf) {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}
	if content, _ := os.ReadFile(pdf); !strings.HasPrefix(string(content), "%PDF-") {
		t.Errorf("the PDF starts %q", content[:min(len(content), 8)])
	}
	if _, stderr, code := run("convert", document); code == 0 || !strings.Contains(stderr, "--force") {
		t.Errorf("over an existing PDF: exit %d, %s", code, stderr)
	}
	if _, stderr, code := run("convert", document, "--force"); code != 0 {
		t.Errorf("with --force: exit %d, %s", code, stderr)
	}
	named := filepath.Join(t.TempDir(), "impreso.pdf")
	if stdout, stderr, code := run("convert", document, "--out", named, "--json"); code != 0 || !strings.Contains(stdout, `"pdf":"`+named+`"`) {
		t.Errorf("--out: exit %d, %s %s", code, stdout, stderr)
	}
}
