package integration_test

// The four ways a XAdES signature holds what it signs, each checked with the
// complete XML-Signature check: enveloped (the default), enveloping, detached
// (the document beside, untouched) and AutoFirma's "XAdES Detached" (a new
// document whose AFIRMA root holds CONTENT and the signature).

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

const pdfBytes = "%PDF-1.4\n%fixture document\n"

func signPackaged(t *testing.T, content, name string, packaging domain.XMLPackaging) string {
	t.Helper()
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	output, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), application.XadesRequest{
		Content: []byte(content), Signer: signer, Level: domain.BES, Packaging: packaging, DocumentName: name,
	})
	if err != nil {
		t.Fatalf("SignXades %s: %v", packaging, err)
	}
	return string(output)
}

// checkPackaged runs the complete check; resolve answers a detached reference.
func checkPackaged(t *testing.T, signed string, resolve xmldsig.Resolver) error {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromString(signed); err != nil {
		t.Fatal(err)
	}
	signature := xmldsig.Signatures(document)[0]
	der, err := base64.StdEncoding.DecodeString(signature.FindElement(".//X509Certificate").Text())
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return xmldsig.Check(document, signature, certificate.PublicKey, resolve)
}

// TestAutoFirmasDetachedHoldsTheContentBesideTheSignature.
func TestAutoFirmasDetachedHoldsTheContentBesideTheSignature(t *testing.T) {
	binary := signPackaged(t, pdfBytes, "solicitud.pdf", domain.XMLInternallyDetached)
	for _, expected := range []string{
		`<AFIRMA Id="AFIRMA-Root-`,
		`MimeType="application/pdf" Encoding="http://www.w3.org/2000/09/xmldsig#base64">` + base64.StdEncoding.EncodeToString([]byte(pdfBytes)) + `</CONTENT><ds:Signature`,
		`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>`,
	} {
		if !strings.Contains(binary, expected) {
			t.Errorf("a PDF in AutoFirma's detached layout lacks %s", expected)
		}
	}
	// The Base64 transform makes the digest the document's own.
	digest := sha256.Sum256([]byte(pdfBytes))
	if declared := extractDigest(t, binary, 0); declared != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Errorf("the reference digests %s, not the PDF", declared)
	}
	if err := checkPackaged(t, binary, nil); err != nil {
		t.Errorf("binary: %v", err)
	}

	xml := signPackaged(t, `<solicitud xmlns="urn:sede"><a>1</a></solicitud>`, "", domain.XMLInternallyDetached)
	if !strings.Contains(xml, `MimeType="text/xml"><solicitud xmlns="urn:sede"><a>1</a></solicitud></CONTENT>`) {
		t.Errorf("XML goes inside CONTENT as XML:\n%.400s", xml)
	}
	if err := checkPackaged(t, xml, nil); err != nil {
		t.Errorf("XML: %v", err)
	}
	if err := checkPackaged(t, strings.Replace(xml, "<a>1</a>", "<a>2</a>", 1), nil); err == nil {
		t.Error("a changed CONTENT must not verify")
	}
}

// TestADetachedXadesNamesTheDocumentBesideIt and digests its bytes.
func TestADetachedXadesNamesTheDocumentBesideIt(t *testing.T) {
	signed := signPackaged(t, pdfBytes, "acta del pleno.pdf", domain.XMLDetached)
	if !strings.Contains(signed, `URI="acta%20del%20pleno.pdf"><ds:DigestMethod`) {
		t.Errorf("the reference names the file, escaped, without transforms:\n%.600s", signed)
	}
	if strings.Contains(signed, base64.StdEncoding.EncodeToString([]byte(pdfBytes))) {
		t.Error("a detached signature does not carry the document")
	}
	if !strings.HasPrefix(signed[strings.Index(signed, "?>")+2:], "\n<ds:Signature") {
		t.Error("the signature is the root of its own file")
	}
	beside := func(document string) xmldsig.Resolver {
		return func(uri string) ([]byte, error) {
			if uri != "acta%20del%20pleno.pdf" {
				return nil, fmt.Errorf("%w: %s", xmldsig.ErrContentMissing, uri)
			}
			return []byte(document), nil
		}
	}
	if err := checkPackaged(t, signed, beside(pdfBytes)); err != nil {
		t.Errorf("with its document: %v", err)
	}
	if err := checkPackaged(t, signed, beside(pdfBytes+"x")); err == nil {
		t.Error("another document must not verify")
	}
}

// TestAnEnvelopingXadesCarriesAnyFile: Base64 for bytes, XML as XML.
func TestAnEnvelopingXadesCarriesAnyFile(t *testing.T) {
	binary := signPackaged(t, pdfBytes, "", domain.XMLEnveloping)
	if !strings.Contains(binary, `MimeType="application/pdf" Encoding="http://www.w3.org/2000/09/xmldsig#base64">`) ||
		!strings.Contains(binary, `Type="http://www.w3.org/2000/09/xmldsig#Object"`) {
		t.Errorf("enveloping PDF:\n%.600s", binary)
	}
	if err := checkPackaged(t, binary, nil); err != nil {
		t.Errorf("binary: %v", err)
	}
	xml := signPackaged(t, `<acta><punto>1</punto></acta>`, "", domain.XMLEnveloping)
	if !strings.Contains(xml, `MimeType="text/xml"><acta><punto>1</punto></acta></ds:Object>`) {
		t.Errorf("enveloping XML:\n%.600s", xml)
	}
	if err := checkPackaged(t, xml, nil); err != nil {
		t.Errorf("XML: %v", err)
	}
}

// TestAnEnvelopedXadesNeedsXML.
func TestAnEnvelopedXadesNeedsXML(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	_, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), application.XadesRequest{
		Content: []byte(pdfBytes), Signer: signer, Level: domain.BES, Packaging: domain.XMLEnveloped,
	})
	if err == nil || !strings.Contains(err.Error(), "not XML") {
		t.Errorf("an enveloped signature of a PDF: %v", err)
	}
}

// TestPlainXMLDSigHasNoSignedProperties: the document reference alone, in
// every layout, and it verifies.
func TestPlainXMLDSigHasNoSignedProperties(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	for _, packaging := range []domain.XMLPackaging{domain.XMLEnveloped, domain.XMLEnveloping, domain.XMLDetached, domain.XMLInternallyDetached} {
		output, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), application.XadesRequest{
			Content: []byte(`<acta><punto>1</punto></acta>`), Signer: signer, Level: domain.BES,
			Packaging: packaging, DocumentName: "acta.xml", Plain: true,
		})
		if err != nil {
			t.Fatalf("%s: %v", packaging, err)
		}
		signed := string(output)
		if strings.Contains(signed, "QualifyingProperties") || strings.Contains(signed, "xmlns:xades") || strings.Count(signed, "<ds:Reference ") != 1 {
			t.Errorf("%s: plain XMLDSig carries the document reference alone:\n%.500s", packaging, signed)
		}
		resolve := func(string) ([]byte, error) { return []byte(`<acta><punto>1</punto></acta>`), nil }
		if err := checkPackaged(t, signed, resolve); err != nil {
			t.Errorf("%s: %v", packaging, err)
		}
	}
	for name, request := range map[string]application.XadesRequest{
		"a timestamp": {Level: domain.T, TimestampURL: "http://tsa.example.invalid"},
		"a role":      {Level: domain.BES, ClaimedRoles: []string{"emisor"}},
	} {
		request.Content, request.Signer, request.Plain = []byte(`<acta/>`), signer, true
		if _, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), request); err == nil {
			t.Errorf("plain XMLDSig with %s must be refused", name)
		}
	}
}

// TestADetachedXadesSignsSeveralDocuments: a reference and a
// DataObjectFormat for each, and every document must match.
func TestADetachedXadesSignsSeveralDocuments(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	documents := map[string][]byte{"acta.txt": []byte("acta\n"), "plano.pdf": []byte(pdfBytes), "presupuesto.xml": []byte("<p/>")}
	output, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), application.XadesRequest{
		Content: documents["acta.txt"], DocumentName: "acta.txt", Signer: signer, Level: domain.BES, Packaging: domain.XMLDetached,
		MoreDocuments: []application.DetachedDocument{{Name: "plano.pdf", Content: documents["plano.pdf"]}, {Name: "presupuesto.xml", Content: documents["presupuesto.xml"]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed := string(output)
	if strings.Count(signed, "<xades:DataObjectFormat ") != 3 || strings.Count(signed, "<ds:Reference ") != 4 {
		t.Errorf("three documents need three references, three formats and the properties:\n%.900s", signed)
	}
	for _, format := range []string{"text/plain", "application/pdf", "text/xml"} {
		if !strings.Contains(signed, "<xades:MimeType>"+format+"</xades:MimeType>") {
			t.Errorf("no %s format", format)
		}
	}
	resolve := func(changed string) xmldsig.Resolver {
		return func(uri string) ([]byte, error) {
			content, known := documents[uri]
			if !known {
				return nil, fmt.Errorf("%w: %s", xmldsig.ErrContentMissing, uri)
			}
			if uri == changed {
				return append(append([]byte{}, content...), 'x'), nil
			}
			return content, nil
		}
	}
	if err := checkPackaged(t, signed, resolve("")); err != nil {
		t.Errorf("the three documents: %v", err)
	}
	if err := checkPackaged(t, signed, resolve("presupuesto.xml")); err == nil {
		t.Error("a changed third document must not verify")
	}
}

// TestADetachedXadesNamesOfficeDocumentsByTheirKind: an office document's
// bytes are a ZIP; its name says what it is, and the DataObjectFormat says
// it too, for the first document and the others.
func TestADetachedXadesNamesOfficeDocumentsByTheirKind(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	output, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), application.XadesRequest{
		Content: []byte("PK\x03\x04memoria"), DocumentName: "memoria.odt", Signer: signer, Level: domain.BES, Packaging: domain.XMLDetached,
		MoreDocuments: []application.DetachedDocument{{Name: "informe.docx", Content: []byte("PK\x03\x04informe")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"application/vnd.oasis.opendocument.text",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document"} {
		if !strings.Contains(string(output), "<xades:MimeType>"+format+"</xades:MimeType>") {
			t.Errorf("no %s format:\n%.1200s", format, output)
		}
	}
}
