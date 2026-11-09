package integration_test

// OpenDocument signatures, laid out as LibreOffice lays them out (and checked
// by hand with LibreOffice 26.2 itself): every stream referenced, mimetype
// and the manifest included, the XML ones canonicalised, the rest of the
// package copied byte for byte.

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// odfPackage is a small text document: two XML streams with attributes
// from several namespaces, an RDF manifest (not text/xml), a picture.
func odfPackage(t *testing.T) []byte {
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
	add("mimetype", zip.Store, "application/vnd.oasis.opendocument.text")
	add("content.xml", zip.Deflate, `<?xml version="1.0" encoding="UTF-8"?>`+
		`<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" office:version="1.3">`+
		`<style:font-face style:name="Liberation" svg:font-family="Liberation" style:font-pitch="fixed"/><office:body>Acta</office:body></office:document-content>`)
	add("styles.xml", zip.Deflate, `<office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.3"/>`)
	add("manifest.rdf", zip.Deflate, `<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>`)
	add("Pictures/sello.png", zip.Store, "\x89PNG\r\n\x1a\nfixture")
	add("META-INF/manifest.xml", zip.Deflate, `<?xml version="1.0" encoding="UTF-8"?>`+
		`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">`+
		`<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>`+
		`<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>`+
		`<manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/>`+
		`<manifest:file-entry manifest:full-path="manifest.rdf" manifest:media-type="application/rdf+xml"/>`+
		`<manifest:file-entry manifest:full-path="Pictures/sello.png" manifest:media-type="image/png"/>`+
		`</manifest:manifest>`)
	writer.Close()
	return output.Bytes()
}

func signOdf(t *testing.T, content []byte) []byte {
	t.Helper()
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	signed, err := infrastructure.NewOdfSigner(infrastructure.NewXadesSigner(nil)).SignOdf(t.Context(),
		application.XadesRequest{Content: content, Signer: signer, Level: domain.BES})
	if err != nil {
		t.Fatalf("SignOdf: %v", err)
	}
	return signed
}

// entries reads a package: names in order, content, method.
func entries(t *testing.T, content []byte) (names []string, files map[string][]byte, methods map[string]uint16) {
	t.Helper()
	archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	files, methods = map[string][]byte{}, map[string]uint16{}
	for _, file := range archive.File {
		reader, _ := file.Open()
		data, _ := io.ReadAll(reader)
		reader.Close()
		names = append(names, file.Name)
		files[file.Name], methods[file.Name] = data, file.Method
	}
	return names, files, methods
}

// checkOdfSignatures runs the complete check on every signature, resolving
// references inside the package.
func checkOdfSignatures(t *testing.T, signed []byte) []error {
	t.Helper()
	_, files, _ := entries(t, signed)
	document := etree.NewDocument()
	if err := document.ReadFromBytes(files["META-INF/documentsignatures.xml"]); err != nil {
		t.Fatal(err)
	}
	resolve := func(uri string) ([]byte, error) {
		if content, ok := files[uri]; ok {
			return content, nil
		}
		return nil, fmt.Errorf("%w: %s", xmldsig.ErrContentMissing, uri)
	}
	var results []error
	for _, signature := range xmldsig.Signatures(document) {
		der, _ := base64.StdEncoding.DecodeString(signature.FindElement(".//X509Certificate").Text())
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, xmldsig.Check(document, signature, certificate.PublicKey, resolve))
	}
	return results
}

// TestAnOpenDocumentIsSignedInsideItself, as LibreOffice signs it.
func TestAnOpenDocumentIsSignedInsideItself(t *testing.T) {
	original := odfPackage(t)
	signed := signOdf(t, original)

	originalNames, originalFiles, _ := entries(t, original)
	names, files, methods := entries(t, signed)
	if names[0] != "mimetype" || methods["mimetype"] != zip.Store {
		t.Errorf("mimetype must stay first and stored: %v", names)
	}
	for _, name := range originalNames {
		if !bytes.Equal(files[name], originalFiles[name]) {
			t.Errorf("%s changed", name)
		}
	}
	signatures := string(files["META-INF/documentsignatures.xml"])
	if !strings.Contains(signatures, `<document-signatures xmlns="urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0" version="1.2">`) {
		t.Errorf("the signatures file's root: %.200s", signatures)
	}
	for uri, canonical := range map[string]bool{"mimetype": false, "content.xml": true, "styles.xml": true,
		"META-INF/manifest.xml": true, "manifest.rdf": false, "Pictures/sello.png": false} {
		reference := regexp.MustCompile(`<ds:Reference Id="[^"]+" URI="` + regexp.QuoteMeta(uri) + `">(<ds:Transforms>)?`).FindStringSubmatch(signatures)
		if reference == nil {
			t.Errorf("no reference to %s", uri)
			continue
		}
		if (reference[1] != "") != canonical {
			t.Errorf("%s: canonicalised %v, want %v", uri, reference[1] != "", canonical)
		}
	}
	if strings.Contains(signatures, `URI="META-INF/documentsignatures.xml"`) {
		t.Error("the signatures file does not sign itself")
	}
	for _, err := range checkOdfSignatures(t, signed) {
		if err != nil {
			t.Errorf("check: %v", err)
		}
	}
}

// TestASecondSignatureKeepsTheFirst, and a non-ODF file is refused.
func TestASecondSignatureKeepsTheFirst(t *testing.T) {
	twice := signOdf(t, signOdf(t, odfPackage(t)))
	results := checkOdfSignatures(t, twice)
	if len(results) != 2 {
		t.Fatalf("%d signatures, want 2", len(results))
	}
	for index, err := range results {
		if err != nil {
			t.Errorf("signature %d: %v", index+1, err)
		}
	}

	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	_, err := infrastructure.NewOdfSigner(infrastructure.NewXadesSigner(nil)).SignOdf(t.Context(),
		application.XadesRequest{Content: []byte("%PDF-1.4"), Signer: signer, Level: domain.BES})
	if !errors.Is(err, infrastructure.ErrNotOpenDocument) {
		t.Errorf("a PDF: %v", err)
	}
}
