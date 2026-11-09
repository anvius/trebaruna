package odf_test

// OpenDocument signatures, judged on a file LibreOffice signed itself
// (testdata/PROVENANCE.md): it verifies, a changed stream breaks it, a
// stream added afterwards is named, and an unsigned file has no signatures.

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func verify(t *testing.T, path string) []domain.SignerReport {
	t.Helper()
	reports, err := infrastructure.NewOdfVerifier(infrastructure.NewXadesVerifier()).Extract(path)
	if err != nil {
		t.Fatal(err)
	}
	return reports
}

// rewrite copies a package, changing or adding one entry.
func rewrite(t *testing.T, name string, change func(string, []byte) []byte, added map[string]string) string {
	t.Helper()
	source, err := zip.OpenReader(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range source.File {
		reader, _ := file.Open()
		content, _ := io.ReadAll(reader)
		reader.Close()
		if change != nil {
			content = change(file.Name, content)
		}
		entry, _ := writer.CreateHeader(&zip.FileHeader{Name: file.Name, Method: file.Method})
		entry.Write(content)
	}
	for entryName, content := range added {
		entry, _ := writer.Create(entryName)
		entry.Write([]byte(content))
	}
	writer.Close()
	path := filepath.Join(t.TempDir(), name)
	os.WriteFile(path, output.Bytes(), 0o600)
	return path
}

// TestLibreOfficesSignatureVerifies.
func TestLibreOfficesSignatureVerifies(t *testing.T) {
	reports := verify(t, filepath.Join("testdata", "libreoffice-signed.odt"))
	if len(reports) != 1 || reports[0].Integrity != domain.StatusGood || reports[0].Format != "XAdES" {
		t.Fatalf("%+v", reports)
	}
	if reports[0].SignerName != "Prueba" {
		t.Errorf("signer %q", reports[0].SignerName)
	}
}

// TestAChangedStreamBreaksIt.
func TestAChangedStreamBreaksIt(t *testing.T) {
	changed := rewrite(t, "libreoffice-signed.odt", func(name string, content []byte) []byte {
		if name == "content.xml" {
			return bytes.Replace(content, []byte("aprobaci"), []byte("denegaci"), 1)
		}
		return content
	}, nil)
	if reports := verify(t, changed); reports[0].Integrity != domain.StatusBad {
		t.Errorf("a changed content.xml: %s", reports[0].Integrity)
	}
}

// TestAStreamAddedLaterIsNamed: it is not signed, whatever the file says.
func TestAStreamAddedLaterIsNamed(t *testing.T) {
	added := rewrite(t, "libreoffice-signed.odt", nil, map[string]string{"Pictures/añadido.png": "x"})
	reports := verify(t, added)
	found := false
	for _, finding := range reports[0].Findings {
		found = found || (finding.Code == "container.unsigned_files" && strings.Contains(finding.Detail, "Pictures/añadido.png"))
	}
	if !found || reports[0].Integrity != domain.StatusGood {
		t.Errorf("an added picture: %+v", reports[0].Findings)
	}
}

// TestAnUnsignedDocumentHasNoSignatures, without an error.
func TestAnUnsignedDocumentHasNoSignatures(t *testing.T) {
	if reports := verify(t, filepath.Join("testdata", "unsigned.odt")); len(reports) != 0 {
		t.Errorf("%d reports", len(reports))
	}
	if _, err := infrastructure.NewOdfVerifier(infrastructure.NewXadesVerifier()).Extract(filepath.Join("..", "asic", "testdata", "asics-cades.asics")); err == nil {
		t.Error("an ASiC container is not an OpenDocument file")
	}
}
