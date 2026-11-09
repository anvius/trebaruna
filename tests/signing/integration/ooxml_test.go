package integration_test

// Office Open XML signatures, laid out as Microsoft Office lays them out (and
// checked by hand with LibreOffice 26.2 and xmlsec1): one signature part under
// _xmlsignatures whose Manifest covers the package but its document
// properties, the relationships through the RelationshipTransform, and the
// rest of the package copied byte for byte.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/opc"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// ooxmlPackage is a small Word document: relationships written with line
// breaks, as LibreOffice writes them, a picture, an external hyperlink, and
// the document properties a signature leaves out.
func ooxmlPackage(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	add := func(name string, method uint16, content string) {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		entry.Write([]byte(content))
	}
	add("[Content_Types].xml", zip.Deflate, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+"\n"+
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`+
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`+
		`<Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/>`+
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`+
		`<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>`+
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>`+
		`<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>`+
		`</Types>`)
	add("_rels/.rels", zip.Deflate, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+"\n  "+
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>`+"\n  "+
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>`+"\n  "+
		`<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>`+"\n"+
		`</Relationships>`+"\n")
	add("word/document.xml", zip.Deflate, `<?xml version="1.0" encoding="UTF-8"?>`+
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Acta: aprobación</w:t></w:r></w:p></w:body></w:document>`)
	add("word/styles.xml", zip.Deflate, `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>`)
	add("word/_rels/document.xml.rels", zip.Deflate, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`+
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/sello.png"/>`+
		`<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org/?a=1&amp;b=2" TargetMode="External"/>`+"\n"+
		`</Relationships>`)
	add("word/media/sello.png", zip.Store, "\x89PNG\r\n\x1a\nfixture")
	add("docProps/core.xml", zip.Deflate, `<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"/>`)
	add("docProps/app.xml", zip.Deflate, `<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"/>`)
	writer.Close()
	return output.Bytes()
}

func signOoxml(t *testing.T, content []byte, request application.XadesRequest, timestamps infrastructure.Timestamper) []byte {
	t.Helper()
	request.Signer = xadesTestSigner(t)
	if request.Level == "" {
		request.Level = domain.BES
	}
	request.Content = content
	signed, err := infrastructure.NewOoxmlSigner(infrastructure.NewXadesSigner(timestamps)).SignOoxml(context.Background(), request)
	if err != nil {
		t.Fatalf("SignOoxml: %v", err)
	}
	return signed
}

// signatureParts reads the package's signatures, in the origin's order.
func signatureParts(t *testing.T, pkg *opc.Package) []*etree.Document {
	t.Helper()
	parts, err := pkg.SignatureParts()
	if err != nil {
		t.Fatal(err)
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

// checkSignature checks a signature part whole: its XML signature, and its
// Manifest against the package.
func checkSignature(t *testing.T, pkg *opc.Package, document *etree.Document) opc.ManifestCheck {
	t.Helper()
	signature := document.Root()
	if err := xmldsig.Check(document, signature, certificateIn(t, signature).PublicKey, nil); err != nil {
		t.Fatalf("XML signature: %v", err)
	}
	manifests := opc.Manifests(document)
	if len(manifests) != 1 {
		t.Fatalf("%d manifests", len(manifests))
	}
	check, err := pkg.CheckManifest(manifests[0])
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	return check
}

// TestAnOfficeDocumentIsSignedInsideItself, as Office signs it.
func TestAnOfficeDocumentIsSignedInsideItself(t *testing.T) {
	original := ooxmlPackage(t)
	signed := signOoxml(t, original, application.XadesRequest{}, nil)

	before, beforeFiles, beforeMethods := entries(t, original)
	after, afterFiles, afterMethods := entries(t, signed)
	if want := append(append([]string{}, before...), "_xmlsignatures/origin.sigs",
		"_xmlsignatures/_rels/origin.sigs.rels", "_xmlsignatures/sig1.xml"); !slices.Equal(after, want) {
		t.Errorf("entries %v, want %v", after, want)
	}
	if missing := undated(t, signed, "_xmlsignatures/origin.sigs", "_xmlsignatures/_rels/origin.sigs.rels", "_xmlsignatures/sig1.xml",
		"[Content_Types].xml"); len(missing) > 0 {
		t.Errorf("written without a date: %v", missing)
	}
	for _, name := range []string{"word/document.xml", "word/styles.xml", "word/media/sello.png", "docProps/core.xml", "docProps/app.xml"} {
		if !bytes.Equal(beforeFiles[name], afterFiles[name]) || beforeMethods[name] != afterMethods[name] {
			t.Errorf("%s was not copied as it was", name)
		}
	}
	// The relationships are written compactly, so every implementation of
	// the transform digests them alike; the package now names the origin.
	for _, name := range []string{"_rels/.rels", "word/_rels/document.xml.rels"} {
		content := string(afterFiles[name])
		if inside := content[strings.Index(content, "<Relationships"):strings.Index(content, "</Relationships>")]; strings.Contains(inside, "\n") {
			t.Errorf("%s keeps its line breaks:\n%s", name, afterFiles[name])
		}
	}
	if !strings.Contains(string(afterFiles["_rels/.rels"]), `Target="_xmlsignatures/origin.sigs"`) {
		t.Errorf("no origin: %s", afterFiles["_rels/.rels"])
	}
	types := string(afterFiles["[Content_Types].xml"])
	if !strings.Contains(types, `<Override PartName="/_xmlsignatures/sig1.xml" ContentType="application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"/>`) ||
		!strings.Contains(types, `<Default Extension="sigs" ContentType="application/vnd.openxmlformats-package.digital-signature-origin"/>`) {
		t.Errorf("content types: %s", types)
	}

	pkg, err := opc.Open(signed)
	if err != nil {
		t.Fatal(err)
	}
	documents := signatureParts(t, pkg)
	if len(documents) != 1 || documents[0].Root().SelectAttrValue("Id", "") != "idPackageSignature" {
		t.Fatalf("signatures: %d", len(documents))
	}
	check := checkSignature(t, pkg, documents[0])
	slices.Sort(check.Covered)
	want := []string{"/_rels/.rels", "/word/_rels/document.xml.rels", "/word/document.xml", "/word/media/sello.png", "/word/styles.xml"}
	if !slices.Equal(check.Covered, want) || len(check.LibxmlsecForm) > 0 {
		t.Errorf("covered %v, want %v; libxmlsec form %v", check.Covered, want, check.LibxmlsecForm)
	}
	covered := map[string]bool{}
	for _, part := range check.Covered {
		covered[part] = true
	}
	if unsigned := pkg.Unsigned(covered); len(unsigned) > 0 {
		t.Errorf("unsigned %v", unsigned)
	}

	// The package's relationships are signed but for the document properties
	// and the origin; the document's, every one, the hyperlink included.
	sources := map[string][]string{}
	for _, reference := range opc.Manifests(documents[0])[0].SelectElements("Reference") {
		for _, selector := range reference.FindElements("./Transforms/Transform/RelationshipReference") {
			uri, _, _ := strings.Cut(reference.SelectAttrValue("URI", ""), "?")
			sources[uri] = append(sources[uri], selector.SelectAttrValue("SourceId", ""))
		}
	}
	if strings.Join(sources["/_rels/.rels"], " ") != "rId1" || strings.Join(sources["/word/_rels/document.xml.rels"], " ") != "rId1 rId2 rId3" {
		t.Errorf("signed relationships %v", sources)
	}
}

// TestASecondOfficeSignatureKeepsTheFirst: nothing the first covers is
// touched, and the relationships are not rewritten again.
func TestASecondOfficeSignatureKeepsTheFirst(t *testing.T) {
	once := signOoxml(t, ooxmlPackage(t), application.XadesRequest{}, nil)
	twice := signOoxml(t, once, application.XadesRequest{}, nil)
	_, onceFiles, _ := entries(t, once)
	_, twiceFiles, _ := entries(t, twice)
	for _, name := range []string{"_rels/.rels", "word/_rels/document.xml.rels", "_xmlsignatures/sig1.xml"} {
		if !bytes.Equal(onceFiles[name], twiceFiles[name]) {
			t.Errorf("%s changed", name)
		}
	}
	pkg, err := opc.Open(twice)
	if err != nil {
		t.Fatal(err)
	}
	documents := signatureParts(t, pkg)
	if len(documents) != 2 {
		t.Fatalf("%d signatures", len(documents))
	}
	for _, document := range documents {
		checkSignature(t, pkg, document)
	}
}

// TestALibreOfficeSignatureIsFollowedInItsForm: LibreOffice digested its
// relationships in libxmlsec's form, so the new signature does too and both
// verify in LibreOffice; LibreOffice's is left valid.
func TestALibreOfficeSignatureIsFollowedInItsForm(t *testing.T) {
	signedByLibreOffice, err := os.ReadFile(filepath.Join("..", "..", "verification", "ooxml", "testdata", "libreoffice-signed.docx"))
	if err != nil {
		t.Fatal(err)
	}
	signed := signOoxml(t, signedByLibreOffice, application.XadesRequest{}, nil)
	_, before, _ := entries(t, signedByLibreOffice)
	_, after, _ := entries(t, signed)
	if !bytes.Equal(before["word/_rels/document.xml.rels"], after["word/_rels/document.xml.rels"]) {
		t.Error("the relationships LibreOffice signed were rewritten")
	}
	pkg, err := opc.Open(signed)
	if err != nil {
		t.Fatal(err)
	}
	documents := signatureParts(t, pkg)
	if len(documents) != 2 {
		t.Fatalf("%d signatures", len(documents))
	}
	for index, document := range documents {
		if check := checkSignature(t, pkg, document); len(check.LibxmlsecForm) != 2 {
			t.Errorf("signature %d: libxmlsec form %v", index+1, check.LibxmlsecForm)
		}
	}
}

// TestAnOfficeSignatureTakesATimestamp: XAdES-T, read back by the verifier.
func TestAnOfficeSignatureTakesATimestamp(t *testing.T) {
	tsa := newLocalTSA(t)
	signed := signOoxml(t, ooxmlPackage(t), application.XadesRequest{Level: domain.T, TimestampURL: "http://tsa.example.invalid"}, tsa)
	path := filepath.Join(t.TempDir(), "acta_signed.docx")
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewOoxmlVerifier(verificationinfra.NewXadesVerifier()).Extract(path)
	if err != nil || len(reports) != 1 {
		t.Fatalf("%+v %v", reports, err)
	}
	if got := reports[0]; got.Integrity != verificationdomain.StatusGood || !got.Timestamped || !got.TimestampEvidence.Bound {
		t.Errorf("%+v", got)
	}
	if tsa.requests != 1 {
		t.Errorf("%d timestamp requests", tsa.requests)
	}
}

// TestWhatIsNotAnOfficeDocumentIsRefused.
func TestWhatIsNotAnOfficeDocumentIsRefused(t *testing.T) {
	_, err := infrastructure.NewOoxmlSigner(infrastructure.NewXadesSigner(nil)).SignOoxml(context.Background(),
		application.XadesRequest{Content: []byte("%PDF-1.7"), Signer: xadesTestSigner(t), Level: domain.BES})
	if !errors.Is(err, infrastructure.ErrNotOfficeOpenXML) {
		t.Errorf("a PDF: %v", err)
	}
}

// certificateIn reads the signing certificate a signature carries.
func certificateIn(t *testing.T, signature *etree.Element) *x509.Certificate {
	t.Helper()
	element := signature.FindElement(".//X509Certificate")
	if element == nil {
		t.Fatal("no certificate in the signature")
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(element.Text()))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
