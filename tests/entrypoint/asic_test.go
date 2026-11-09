package cli_test

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// containerEntries lists a container's entries and the first one's method.
func containerEntries(t *testing.T, path string) ([]string, uint16) {
	t.Helper()
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	var names []string
	for _, file := range archive.File {
		names = append(names, file.Name)
	}
	return names, archive.File[0].Method
}

// TestSignIntoAnASiCSContainer, CAdES and XAdES, and verify it.
func TestSignIntoAnASiCSContainer(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeDocument(t, "informe.pdf", "%PDF-1.4\n%informe\n")
	for format, signature := range map[string]string{"cades": "META-INF/signature.p7s", "xades": "META-INF/signatures.xml"} {
		output := document + "." + format + ".asics"
		if _, stderr, code := run("sign", document, "--p12", key, "--format", format, "--asic", "s", "--out", output); code != 0 {
			t.Fatalf("%s: exit %d: %s", format, code, stderr)
		}
		names, method := containerEntries(t, output)
		if strings.Join(names, " ") != "mimetype informe.pdf "+signature || method != zip.Store {
			t.Errorf("%s container: %v (mimetype method %d)", format, names, method)
		}
		stdout, _, _ := run("verify", output, "--json")
		if !strings.Contains(stdout, `"integrity": "good"`) || !strings.Contains(stdout, `"detail": "informe.pdf"`) {
			t.Errorf("%s: verify %s", format, stdout)
		}
	}
	if _, err := os.Stat(document + ".asics"); err == nil {
		t.Error("--out was ignored")
	}
	if _, _, code := run("sign", document, "--p12", key, "--format", "pades", "--asic", "s"); code == 0 {
		t.Error("a PAdES signature goes inside the PDF, not into a container")
	}
}

// TestTheAsicCommandPacksADetachedSignatureUnderMETAINF and explains what it
// cannot pack.
func TestTheAsicCommandPacksADetachedSignatureUnderMETAINF(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeDocument(t, "acta.txt", "acta\n")
	if _, stderr, code := run("sign", document, "--p12", key, "--format", "cades", "--detached"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if _, stderr, code := run("asic", document, document+".p7s"); code != 0 {
		t.Fatalf("asic: exit %d: %s", code, stderr)
	}
	names, _ := containerEntries(t, document+".asics")
	if strings.Join(names, " ") != "mimetype acta.txt META-INF/signature.p7s" {
		t.Errorf("container: %v", names)
	}
	if result := verifyJSON(t, document+".asics"); result.Signers[0].Integrity != "good" {
		t.Errorf("packed container: %+v", result.Signers[0])
	}

	embedded := writeDocument(t, "acta.txt.p7m", "x")
	xml := writeDocument(t, "acta.txt.xsig", "<x/>")
	for _, arguments := range [][]string{{document, embedded}, {document, xml}, {document, document + ".p7s", "--type", "e"}} {
		_, stderr, code := run(append([]string{"asic"}, arguments...)...)
		if code == 0 || !strings.Contains(stderr, "sign") {
			t.Errorf("%v: exit %d, %q", arguments, code, stderr)
		}
	}
}

// TestSignSeveralDocumentsIntoAnASiCE: one signature over all of them, and a
// changed one inside the container is caught.
func TestSignSeveralDocumentsIntoAnASiCE(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	first := writeDocument(t, "acta.txt", "acta\n")
	second := writeDocument(t, "plano.pdf", "%PDF-1.4\n%plano\n")
	for _, format := range []string{"cades", "xades"} {
		output := first + "." + format + ".asice"
		if _, stderr, code := run("sign", first, second, "--p12", key, "--format", format, "--asic", "e", "--out", output); code != 0 {
			t.Fatalf("%s: exit %d: %s", format, code, stderr)
		}
		stdout, _, _ := run("verify", output, "--json")
		if !strings.Contains(stdout, `"integrity": "good"`) || !strings.Contains(stdout, `"detail": "acta.txt, plano.pdf"`) {
			t.Errorf("%s: %s", format, stdout)
		}
		changed := rewriteEntry(t, output, "plano.pdf", []byte("%PDF-1.4\n%otro plano\n"))
		if result := verifyJSON(t, changed); result.Verdict != "broken" {
			t.Errorf("%s with a changed document: %s", format, result.Verdict)
		}
	}
}

// rewriteEntry copies a container with one entry's content replaced.
func rewriteEntry(t *testing.T, path, name string, content []byte) string {
	t.Helper()
	source, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target := path + ".changed.asice"
	file, err := os.Create(target)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for _, entry := range source.File {
		data := content
		if entry.Name != name {
			reader, _ := entry.Open()
			data, _ = io.ReadAll(reader)
			reader.Close()
		}
		out, _ := writer.CreateHeader(&zip.FileHeader{Name: entry.Name, Method: entry.Method})
		out.Write(data)
	}
	writer.Close()
	file.Close()
	return target
}

// TestSignAnOpenDocumentAndVerifyIt from the command line.
func TestSignAnOpenDocumentAndVerifyIt(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	source, err := os.ReadFile(filepath.Join("..", "verification", "odf", "testdata", "unsigned.odt"))
	if err != nil {
		t.Fatal(err)
	}
	document := writeDocument(t, "acta.odt", string(source))
	if _, stderr, code := run("sign", document, "--p12", key); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	signed := strings.TrimSuffix(document, ".odt") + "_signed.odt"
	if result := verifyJSON(t, signed); result.Signers[0].Integrity != "good" {
		t.Errorf("verify: %+v", result.Signers[0])
	}
	if _, _, code := run("sign", document, "--p12", key, "--format", "odf", "--detached"); code == 0 {
		t.Error("an OpenDocument signature is never detached")
	}
}

// TestSignAnOfficeDocumentAndVerifyIt: a Word file LibreOffice made is
// signed inside itself, verifies, and takes a second signature.
func TestSignAnOfficeDocumentAndVerifyIt(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	source, err := os.ReadFile(filepath.Join("..", "verification", "ooxml", "testdata", "unsigned.docx"))
	if err != nil {
		t.Fatal(err)
	}
	document := writeDocument(t, "acta.docx", string(source))
	if _, stderr, code := run("sign", document, "--p12", key); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	signed := strings.TrimSuffix(document, ".docx") + "_signed.docx"
	if result := verifyJSON(t, signed); result.Signers[0].Integrity != "good" {
		t.Errorf("verify: %+v", result.Signers)
	}
	if _, stderr, code := run("sign", signed, "--p12", key); code != 0 {
		t.Fatalf("second signature: exit %d: %s", code, stderr)
	}
	twice := strings.TrimSuffix(signed, ".docx") + "_signed.docx"
	stdout, _, _ := run("verify", twice, "--json")
	if strings.Count(stdout, `"integrity": "good"`) != 2 {
		t.Errorf("verify twice: %s", stdout)
	}
	if _, _, code := run("sign", document, "--p12", key, "--format", "ooxml", "--detached"); code == 0 {
		t.Error("an Office Open XML signature is never detached")
	}
}
