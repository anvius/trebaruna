package asic_test

// ASiC containers built with zip, OpenSSL and xmlsec1 (testdata/PROVENANCE.md):
// each signature is judged against the files it covers, a file no signature
// covers is reported, and a container that tries to write outside itself, or
// is not ASiC, is refused.

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

func verifier() *infrastructure.AsicVerifier {
	return infrastructure.NewAsicVerifier(infrastructure.NewCadesVerifier(), infrastructure.NewXadesVerifier())
}

func finding(report domain.SignerReport, code string) (domain.Finding, bool) {
	for _, candidate := range report.Findings {
		if candidate.Code == code {
			return candidate, true
		}
	}
	return domain.Finding{}, false
}

// rewrite copies a container, replacing entries (nil removes one) and adding
// others; mimetype stays first and stored.
func rewrite(t *testing.T, name string, changes map[string][]byte) string {
	t.Helper()
	source, err := zip.OpenReader(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	written := map[string]bool{}
	write := func(entryName string, content []byte) {
		method := zip.Deflate
		if entryName == "mimetype" {
			method = zip.Store
		}
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: entryName, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		entry.Write(content)
		written[entryName] = true
	}
	for _, file := range source.File {
		if file.FileInfo().IsDir() {
			continue
		}
		content, replaced := changes[file.Name]
		if !replaced {
			reader, _ := file.Open()
			content, _ = io.ReadAll(reader)
			reader.Close()
		} else if content == nil {
			continue
		}
		write(file.Name, content)
	}
	for entryName, content := range changes {
		if !written[entryName] && content != nil {
			write(entryName, content)
		}
	}
	writer.Close()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestContainersFromOtherToolsVerify.
func TestContainersFromOtherToolsVerify(t *testing.T) {
	cases := map[string]string{
		"asics-cades.asics": "informe.pdf",
		"asice-cades.asice": "a.txt, docs/b.pdf",
		"asics-xades.asics": "informe.pdf",
		"asice-xades.asice": "a.txt, docs/b.pdf",
	}
	for name, covers := range cases {
		reports, err := verifier().Extract(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(reports) != 1 || reports[0].Integrity != domain.StatusGood {
			t.Errorf("%s: %+v", name, reports)
			continue
		}
		if covered, ok := finding(reports[0], "container.covers"); !ok || covered.Detail != covers {
			t.Errorf("%s covers %q, want %q", name, covered.Detail, covers)
		}
		if _, unsigned := finding(reports[0], "container.unsigned_files"); unsigned {
			t.Errorf("%s: every file is signed", name)
		}
		if _, leaked := finding(reports[0], "content.detached"); leaked {
			t.Errorf("%s: the unpacked copies' paths must not reach the report", name)
		}
	}
}

// TestAFileNoSignatureCoversIsReported: an added document must not pass as
// signed.
func TestAFileNoSignatureCoversIsReported(t *testing.T) {
	reports, err := verifier().Extract(filepath.Join("testdata", "asice-xades-unsigned-file.asice"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned, ok := finding(reports[0], "container.unsigned_files")
	if !ok || unsigned.Detail != "notas.txt" || unsigned.Status != domain.StatusWarn {
		t.Errorf("unsigned files: %+v", unsigned)
	}
	added := rewrite(t, "asics-cades.asics", map[string][]byte{"anexo.pdf": []byte("%PDF-1.4\n%anexo\n")})
	reports, err = verifier().Extract(added)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := finding(reports[0], "container.unsigned_files"); !ok {
		t.Error("a file added to an ASiC-S container is unsigned")
	}
}

// TestAChangedFileOfAContainerIsCaught, whatever signs it.
func TestAChangedFileOfAContainerIsCaught(t *testing.T) {
	changes := map[string]map[string][]byte{
		"asics-cades.asics": {"informe.pdf": []byte("%PDF-1.4\n%informe falso\n")},
		"asice-cades.asice": {"docs/b.pdf": []byte("%PDF-1.4\n%otro anexo\n")},
		"asics-xades.asics": {"informe.pdf": []byte("%PDF-1.4\n%informe falso\n")},
		"asice-xades.asice": {"a.txt": []byte("acta cambiada\n")},
	}
	for name, change := range changes {
		reports, err := verifier().Extract(rewrite(t, name, change))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if reports[0].Integrity != domain.StatusBad {
			t.Errorf("%s with a changed file: %s", name, reports[0].Integrity)
		}
	}
	reports, err := verifier().Extract(rewrite(t, "asice-cades.asice", map[string][]byte{"a.txt": nil}))
	if err != nil {
		t.Fatal(err)
	}
	if reports[0].Integrity != domain.StatusBad {
		t.Errorf("a file the manifest lists is gone: %s", reports[0].Integrity)
	}
}

// TestACadesWithoutItsManifestCannotBeCompared: unknown, not broken.
func TestACadesWithoutItsManifestCannotBeCompared(t *testing.T) {
	reports, err := verifier().Extract(rewrite(t, "asice-cades.asice", map[string][]byte{"META-INF/ASiCManifest.xml": nil}))
	if err != nil {
		t.Fatal(err)
	}
	if reports[0].Integrity != domain.StatusUnknown {
		t.Errorf("without the manifest: %s", reports[0].Integrity)
	}
}

// TestContainersThatAreNotWhatTheySayAreRefused.
func TestContainersThatAreNotWhatTheySayAreRefused(t *testing.T) {
	for what, change := range map[string]map[string][]byte{
		"an entry outside the container": {"../evil.txt": []byte("x")},
		"an OpenDocument file":           {"mimetype": []byte("application/vnd.oasis.opendocument.text")},
		"no signature":                   {"META-INF/signature.p7s": nil},
	} {
		if _, err := verifier().Extract(rewrite(t, "asics-cades.asics", change)); err == nil {
			t.Errorf("%s: accepted", what)
		} else if !strings.Contains(err.Error(), "container") {
			t.Errorf("%s: %v", what, err)
		}
	}
}
