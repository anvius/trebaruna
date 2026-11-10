package integration_test

// LibreOffice prints a document to PDF headless, with a profile of its own
// thrown away after; without LibreOffice, or with a file it cannot read,
// the conversion says so.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

func TestLibreOfficePrintsADocumentToPDF(t *testing.T) {
	if _, err := exec.LookPath("soffice"); err != nil {
		t.Skip("LibreOffice (soffice) is not installed")
	}
	path := filepath.Join(t.TempDir(), "acta.rtf")
	if err := os.WriteFile(path, []byte(`{\rtf1\ansi\deff0{\fonttbl{\f0 Liberation Serif;}}\f0\fs24 Acta de la junta.\par}`), 0o600); err != nil {
		t.Fatal(err)
	}
	document, _ := domain.OpenDocument(path)
	converted, release, err := infrastructure.LibreOffice{}.ConvertToPDF(context.Background(), document)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(converted.Path())
	if err != nil || !strings.HasPrefix(string(content), "%PDF-") || converted.Name() != "acta.pdf" {
		t.Fatalf("%s: %v %q", converted.Path(), err, content[:min(len(content), 8)])
	}
	if _, err := exec.LookPath("pdftotext"); err == nil {
		if text, _ := exec.Command("pdftotext", converted.Path(), "-").Output(); !strings.Contains(string(text), "Acta") {
			t.Errorf("the PDF reads %q", text)
		}
	}
	release()
	if _, err := os.Stat(filepath.Dir(converted.Path())); !errors.Is(err, os.ErrNotExist) {
		t.Error("the PDF's folder outlived release")
	}

	broken := filepath.Join(t.TempDir(), "roto.docx")
	os.WriteFile(broken, []byte("PK\x03\x04 not a document"), 0o600)
	document, _ = domain.OpenDocument(broken)
	if _, _, err := (infrastructure.LibreOffice{}).ConvertToPDF(context.Background(), document); err == nil || !strings.Contains(err.Error(), "could not turn roto.docx") {
		t.Errorf("a broken document: %v", err)
	}
}

func TestWithoutLibreOfficeTheConversionSaysSo(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	path := filepath.Join(t.TempDir(), "acta.odt")
	os.WriteFile(path, []byte("x"), 0o600)
	document, _ := domain.OpenDocument(path)
	if _, _, err := (infrastructure.LibreOffice{}).ConvertToPDF(context.Background(), document); !errors.Is(err, infrastructure.ErrNoOfficeSuite) {
		t.Errorf("without LibreOffice: %v", err)
	}
}
