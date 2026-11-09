package opc_test

// The OPC package against what Microsoft Office and LibreOffice wrote: every
// part digest Office computed, relationships through the RelationshipTransform
// included, is what this package computes; LibreOffice's relationships match
// in libxmlsec's form; changed, retyped and added parts are named.

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/opc"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// signedFiles are the packages Office and LibreOffice signed (see the
// PROVENANCE file beside them).
const signedFiles = "../../verification/ooxml/testdata"

// officeSigned are the files Office signed.
var officeSigned = []string{
	"ms-office-2010-signed.docx", "ms-office-2010-signed.xlsx", "ms-office-2010-signed.pptx",
	"office2007prettyPrintedRels.docx", "Office2010-SP1-XAdES-X-L.docx",
	"hello-world-signed-twice.docx", "hyperlink-example-signed.docx",
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(signedFiles, name))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func open(t *testing.T, content []byte) *opc.Package {
	t.Helper()
	pkg, err := opc.Open(content)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

// signatures reads every signature part of the package.
func signatures(t *testing.T, pkg *opc.Package) []*etree.Document {
	t.Helper()
	parts, err := pkg.SignatureParts()
	if err != nil || len(parts) == 0 {
		t.Fatalf("signature parts %v: %v", parts, err)
	}
	var documents []*etree.Document
	for _, part := range parts {
		content, found := pkg.Part(part)
		if !found {
			t.Fatalf("%s is linked but missing", part)
		}
		document := etree.NewDocument()
		if err := document.ReadFromBytes(content); err != nil {
			t.Fatal(err)
		}
		documents = append(documents, document)
	}
	return documents
}

// check runs every Manifest of the package.
func check(t *testing.T, pkg *opc.Package) (opc.ManifestCheck, error) {
	t.Helper()
	var all opc.ManifestCheck
	for _, document := range signatures(t, pkg) {
		for _, manifest := range opc.Manifests(document) {
			found, err := pkg.CheckManifest(manifest)
			all.Covered = append(all.Covered, found.Covered...)
			all.LibxmlsecForm = append(all.LibxmlsecForm, found.LibxmlsecForm...)
			if err != nil {
				return all, err
			}
		}
	}
	return all, nil
}

// rewrite copies a package, changing entries and adding others.
func rewrite(t *testing.T, content []byte, change func(string, []byte) []byte, added map[string]string) []byte {
	t.Helper()
	source, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range source.File {
		reader, _ := file.Open()
		data, _ := io.ReadAll(reader)
		reader.Close()
		entry, _ := writer.Create(file.Name)
		entry.Write(change(file.Name, data))
	}
	for name, data := range added {
		entry, _ := writer.Create(name)
		entry.Write([]byte(data))
	}
	writer.Close()
	return output.Bytes()
}

func unchanged(_ string, data []byte) []byte { return data }

// TestOfficeManifestsMatchTheirParts, the pretty-printed relationships and
// the external hyperlink among them, and nothing Office signs is left over.
func TestOfficeManifestsMatchTheirParts(t *testing.T) {
	for _, name := range officeSigned {
		pkg := open(t, read(t, name))
		found, err := check(t, pkg)
		if err != nil || len(found.LibxmlsecForm) > 0 {
			t.Errorf("%s: %v, libxmlsec form %v", name, err, found.LibxmlsecForm)
		}
		covered := map[string]bool{}
		for _, part := range found.Covered {
			covered[part] = true
		}
		if unsigned := pkg.Unsigned(covered); len(unsigned) > 0 {
			t.Errorf("%s: unsigned %v", name, unsigned)
		}
	}
}

// TestOfficeSignaturesCheck: the XML signature over the package and Office
// objects verifies with the certificate it carries. The pretty-printed file
// is left out: its SignatureValue does not verify, for xmlsec1 either.
func TestOfficeSignaturesCheck(t *testing.T) {
	for _, name := range officeSigned {
		pkg := open(t, read(t, name))
		for _, document := range signatures(t, pkg) {
			err := xmldsig.Check(document, document.Root(), certificateOf(t, document).PublicKey, nil)
			switch {
			case name == "office2007prettyPrintedRels.docx" && !errors.Is(err, xmldsig.ErrModified):
				t.Errorf("%s: %v, and xmlsec1 rejects its signature value", name, err)
			case name != "office2007prettyPrintedRels.docx" && err != nil:
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

// TestLibreOfficesRelationshipsMatchInLibxmlsecForm: LibreOffice digests
// its relationships with libxmlsec's transform, which keeps a line break as
// <text></text>; the parts are named, not called modified.
func TestLibreOfficesRelationshipsMatchInLibxmlsecForm(t *testing.T) {
	found, err := check(t, open(t, read(t, "libreoffice-signed.docx")))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(found.LibxmlsecForm, " ") != "/_rels/.rels /word/_rels/document.xml.rels" {
		t.Errorf("libxmlsec form %v", found.LibxmlsecForm)
	}
}

// TestTheTransformKeepsTheSelectedRelationshipsOnly, sorted, with
// TargetMode, whatever the formatting and whatever was added later.
func TestTheTransformKeepsTheSelectedRelationshipsOnly(t *testing.T) {
	compact := `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId2" Type="urn:b" Target="b.xml"/><Relationship Id="rId1" Type="urn:a" Target="a.xml"/>` +
		`<Relationship Id="rId3" Type="urn:link" Target="https://example.org/?a=1&amp;b=2" TargetMode="External"/></Relationships>`
	loose := `<?xml version="1.0"?>` + "\n" + `<r:Relationships xmlns:r="http://schemas.openxmlformats.org/package/2006/relationships">` + "\n  " +
		`<r:Relationship Target="a.xml" Id="rId1" Type="urn:a" extra="x"/><!-- comment -->` + "\n  " +
		`<r:Relationship Id="rId9" Type="urn:added" Target="later.xml"/>` + "\n  " +
		`<r:Relationship Id="rId3" Type="urn:link" Target="https://example.org/?a=1&amp;b=2" TargetMode="External"/>` + "\n  " +
		`<r:Relationship Id="rId2" Type="urn:b" Target="b.xml"/>` + "\n" + `</r:Relationships>`
	want := `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Target="a.xml" TargetMode="Internal" Type="urn:a"></Relationship>` +
		`<Relationship Id="rId2" Target="b.xml" TargetMode="Internal" Type="urn:b"></Relationship>` +
		`<Relationship Id="rId3" Target="https://example.org/?a=1&amp;b=2" TargetMode="External" Type="urn:link"></Relationship>` +
		`</Relationships>`
	for name, content := range map[string]string{"compact": compact, "loose": loose} {
		got, err := opc.TransformRelationships([]byte(content), []string{"rId2", "rId1"}, []string{"urn:link"})
		if err != nil || string(got) != want {
			t.Errorf("%s:\n got %s\nwant %s (%v)", name, got, want, err)
		}
	}
}

// TestAChangedPartIsNamed, and every part of the Manifest still counts as
// covered, so nothing is called unsigned on top.
func TestAChangedPartIsNamed(t *testing.T) {
	changed := rewrite(t, read(t, "ms-office-2010-signed.docx"), func(name string, data []byte) []byte {
		if name == "word/document.xml" {
			return bytes.Replace(data, []byte("<w:t>"), []byte("<w:t>X"), 1)
		}
		return data
	}, nil)
	pkg := open(t, changed)
	found, err := check(t, pkg)
	if !errors.Is(err, xmldsig.ErrModified) || !strings.Contains(err.Error(), "/word/document.xml") {
		t.Fatalf("a changed document.xml: %v", err)
	}
	covered := map[string]bool{}
	for _, part := range found.Covered {
		covered[part] = true
	}
	if unsigned := pkg.Unsigned(covered); len(unsigned) > 0 {
		t.Errorf("unsigned %v", unsigned)
	}
}

// TestARetypedPartIsCaught: the content type is part of what is signed.
func TestARetypedPartIsCaught(t *testing.T) {
	retyped := rewrite(t, read(t, "ms-office-2010-signed.docx"), func(name string, data []byte) []byte {
		if name == "[Content_Types].xml" {
			return bytes.Replace(data, []byte("wordprocessingml.styles+xml"), []byte("wordprocessingml.template+xml"), 1)
		}
		return data
	}, nil)
	if _, err := check(t, open(t, retyped)); !errors.Is(err, xmldsig.ErrModified) || !strings.Contains(err.Error(), "/word/styles.xml") {
		t.Errorf("a retyped styles.xml: %v", err)
	}
}

// TestAnAddedPartIsUnsigned, and the metadata Office leaves out is not.
func TestAnAddedPartIsUnsigned(t *testing.T) {
	added := rewrite(t, read(t, "office2007prettyPrintedRels.docx"), unchanged, map[string]string{"word/media/added.png": "png"})
	pkg := open(t, added)
	found, err := check(t, pkg)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, part := range found.Covered {
		covered[part] = true
	}
	if unsigned := pkg.Unsigned(covered); strings.Join(unsigned, " ") != "word/media/added.png" {
		t.Errorf("unsigned %v (the thumbnail and properties are Office's to leave out)", unsigned)
	}
}

// TestNotAPackage.
func TestNotAPackage(t *testing.T) {
	for name, content := range map[string][]byte{"a PDF": []byte("%PDF-1.7"), "an ODF": read(t, "../../odf/testdata/unsigned.odt")} {
		if _, err := opc.Open(content); !errors.Is(err, opc.ErrNotPackage) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func certificateOf(t *testing.T, document *etree.Document) *x509.Certificate {
	t.Helper()
	element := document.FindElement("//X509Certificate")
	if element == nil {
		t.Fatal("no certificate")
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(element.Text()), ""))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
