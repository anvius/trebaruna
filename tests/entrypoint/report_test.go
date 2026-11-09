package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyWritesAReport in the format its name says, in the language asked.
func TestVerifyWritesAReport(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeDocument(t, "acta.txt", "acta\n")
	if _, stderr, code := run("sign", document, "--p12", key, "--format", "cades"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	directory := t.TempDir()
	for name, expected := range map[string]string{"informe.md": "# Rapporto di verifica", "informe.html": `<html lang="it">`, "informe.pdf": "%PDF-1.4"} {
		destination := filepath.Join(directory, name)
		run("verify", document+".p7m", "--report", destination, "--lang", "it")
		content, err := os.ReadFile(destination)
		if err != nil || !strings.HasPrefix(string(content), expected) && !strings.Contains(string(content), expected) {
			t.Errorf("%s: %v %.80q", name, err, content)
		}
	}
	if _, stderr, code := run("verify", document+".p7m", "--report", filepath.Join(directory, "informe.docx")); code == 0 || !strings.Contains(stderr, ".pdf") {
		t.Errorf("a .docx report: exit %d, %s", code, stderr)
	}
}
