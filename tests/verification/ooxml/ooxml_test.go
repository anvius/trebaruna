package ooxml_test

// Office Open XML signatures, judged on files Microsoft Office and LibreOffice
// signed themselves (testdata/PROVENANCE.md): they verify, LibreOffice's with
// a word on its relationships, a changed part breaks them, a part added
// afterwards is named, and an unsigned file has no signatures.

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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
	reports, err := infrastructure.NewOoxmlVerifier(infrastructure.NewXadesVerifier()).Extract(path)
	if err != nil {
		t.Fatal(err)
	}
	return reports
}

// rewrite copies a package, changing entries and adding others.
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

func finding(report domain.SignerReport, code string) (domain.Finding, bool) {
	for _, found := range report.Findings {
		if found.Code == code {
			return found, true
		}
	}
	return domain.Finding{}, false
}

// TestOfficesSignaturesVerify: Word, Excel and PowerPoint, two signers, a
// timestamp, an external hyperlink.
func TestOfficesSignaturesVerify(t *testing.T) {
	for name, signers := range map[string]int{
		"ms-office-2010-signed.docx": 1, "ms-office-2010-signed.xlsx": 1, "ms-office-2010-signed.pptx": 1,
		"Office2010-SP1-XAdES-X-L.docx": 1, "hello-world-signed-twice.docx": 2, "hyperlink-example-signed.docx": 1,
	} {
		reports := verify(t, filepath.Join("testdata", name))
		if len(reports) != signers {
			t.Fatalf("%s: %d signatures", name, len(reports))
		}
		for _, report := range reports {
			// The eID applet's signatures (the two signers) are plain XMLDSig,
			// dated by OPC's SignatureTime.
			format := "XAdES"
			if name == "hello-world-signed-twice.docx" {
				format = "XMLDSig"
			}
			if report.Integrity != domain.StatusGood || report.Format != format || report.SignedAt.IsZero() ||
				!strings.HasPrefix(report.FieldName, "_xmlsignatures/") {
				t.Errorf("%s: %+v", name, report)
			}
			if _, found := finding(report, "container.unsigned_files"); found {
				t.Errorf("%s: parts called unsigned", name)
			}
		}
	}
	if timestamped := verify(t, filepath.Join("testdata", "Office2010-SP1-XAdES-X-L.docx"))[0]; !timestamped.Timestamped {
		t.Error("Office's signature timestamp is not read")
	}
}

// TestLibreOfficesSignatureVerifiesAndItsFormIsTold: LibreOffice's
// relationships digests are libxmlsec's form; the signature is intact and
// the report says Office may not think so.
func TestLibreOfficesSignatureVerifiesAndItsFormIsTold(t *testing.T) {
	reports := verify(t, filepath.Join("testdata", "libreoffice-signed.docx"))
	if len(reports) != 1 || reports[0].Integrity != domain.StatusGood || reports[0].SignerName != "Prueba" {
		t.Fatalf("%+v", reports)
	}
	told, found := finding(reports[0], "relationships.libxmlsec_form")
	if !found || told.Status != domain.StatusWarn || told.Detail != "/_rels/.rels, /word/_rels/document.xml.rels" {
		t.Errorf("libxmlsec form: %+v", told)
	}
}

// TestAChangedPartBreaksIt, and the part is named.
func TestAChangedPartBreaksIt(t *testing.T) {
	changed := rewrite(t, "libreoffice-signed.docx", func(name string, content []byte) []byte {
		if name == "word/document.xml" {
			return bytes.Replace(content, []byte("aprobaci"), []byte("denegaci"), 1)
		}
		return content
	}, nil)
	report := verify(t, changed)[0]
	modified, found := finding(report, "signature.modified")
	if report.Integrity != domain.StatusBad || report.Trust != domain.TrustBroken || !found || !strings.Contains(modified.Detail, "/word/document.xml") {
		t.Errorf("a changed document.xml: %+v", report)
	}
	if _, intact := finding(report, "signature.intact"); intact {
		t.Error("a broken signature is also called intact")
	}
	if _, unsigned := finding(report, "container.unsigned_files"); unsigned {
		t.Error("a changed part is signed, not unsigned")
	}
}

// TestAPartAddedLaterIsNamed.
func TestAPartAddedLaterIsNamed(t *testing.T) {
	added := rewrite(t, "ms-office-2010-signed.docx", nil, map[string]string{"word/media/added.png": "png"})
	report := verify(t, added)[0]
	unsigned, found := finding(report, "container.unsigned_files")
	if report.Integrity != domain.StatusGood || !found || unsigned.Detail != "word/media/added.png" {
		t.Errorf("an added part: %+v", report)
	}
}

// TestASignatureValueThatDoesNotVerifyIsBroken: the pretty-printed file's
// Manifest matches, its SignatureValue does not (xmlsec1 agrees).
func TestASignatureValueThatDoesNotVerifyIsBroken(t *testing.T) {
	if report := verify(t, filepath.Join("testdata", "office2007prettyPrintedRels.docx"))[0]; report.Integrity != domain.StatusBad {
		t.Errorf("%+v", report)
	}
}

// TestAnUnsignedFileHasNoSignatures.
func TestAnUnsignedFileHasNoSignatures(t *testing.T) {
	if reports := verify(t, filepath.Join("testdata", "unsigned.docx")); len(reports) != 0 {
		t.Errorf("%+v", reports)
	}
	if _, err := infrastructure.NewOoxmlVerifier(infrastructure.NewXadesVerifier()).Extract(filepath.Join("..", "odf", "testdata", "unsigned.odt")); err == nil {
		t.Error("an OpenDocument file read as Office Open XML")
	}
}

// TestAManifestOutsideTheSignedObjectsCoversNothing: an Object no reference
// of SignedInfo names is not signed, so a Manifest put there, with the right
// digest of a part added later, does not make that part signed.
func TestAManifestOutsideTheSignedObjectsCoversNothing(t *testing.T) {
	digest := sha256.Sum256([]byte("png"))
	forged := `<Object><Manifest><Reference URI="/word/media/added.png?ContentType=image/png">` +
		`<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
		`<DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</DigestValue></Reference></Manifest></Object></Signature>`
	tampered := rewrite(t, "ms-office-2010-signed.docx", func(name string, content []byte) []byte {
		switch name {
		case "_xmlsignatures/sig1.xml":
			return bytes.Replace(content, []byte("</Signature>"), []byte(forged), 1)
		case "[Content_Types].xml":
			return bytes.Replace(content, []byte("<Default Extension=\"xml\""), []byte("<Default Extension=\"png\" ContentType=\"image/png\"/><Default Extension=\"xml\""), 1)
		}
		return content
	}, map[string]string{"word/media/added.png": "png"})
	report := verify(t, tampered)[0]
	unsigned, found := finding(report, "container.unsigned_files")
	if report.Integrity != domain.StatusGood || !found || unsigned.Detail != "word/media/added.png" {
		t.Errorf("a forged Manifest: %+v", report)
	}
}
