package integration_test

// XAdES was broken in three ways that only an independent verifier caught:
// a duplicated XML declaration, a schema-invalid child order, and missing
// enveloped-signature transforms. These tests pin the structure so those
// regressions cannot return, and verify the digests the way a reader does.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"math/big"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	"github.com/beevik/etree"
)

// TestXadesIsWellFormedXML is the guard for the double-declaration bug.
func TestXadesIsWellFormedXML(t *testing.T) {
	output := signXades(t, `<fattura><numero>1</numero></fattura>`, false)

	decoder := xml.NewDecoder(strings.NewReader(output))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the signed artefact is not well-formed XML: %v", err)
		}
	}

	if strings.Count(output, "<?xml") != 1 {
		t.Errorf("expected exactly one XML declaration, found %d", strings.Count(output, "<?xml"))
	}
}

// TestXadesChildOrderFollowsTheSchema pins SignedInfo, SignatureValue, KeyInfo,
// Object. Verifiers reject any other order outright.
func TestXadesChildOrderFollowsTheSchema(t *testing.T) {
	output := signXades(t, `<fattura><numero>1</numero></fattura>`, false)

	order := []string{"SignedInfo", "SignatureValue", "KeyInfo", "Object"}
	position := -1
	for _, child := range order {
		index := strings.Index(output, "<ds:"+child)
		if index < 0 {
			t.Fatalf("%s is missing from the signature", child)
		}
		if index < position {
			t.Errorf("%s appears out of order", child)
		}
		position = index
	}
}

// TestXadesDeclaresEnvelopedTransform: without it a verifier hashes the document
// including the signature, which did not exist when the digest was taken.
func TestXadesDeclaresEnvelopedTransform(t *testing.T) {
	output := signXades(t, `<fattura><numero>1</numero></fattura>`, false)

	if !strings.Contains(output, "xmldsig#enveloped-signature") {
		t.Error("the document reference must declare the enveloped-signature transform")
	}
}

// TestXadesDocumentDigestMatchesTheEmittedDocument recomputes the digest from
// the file itself, which is what a reader does.
func TestXadesDocumentDigestMatchesTheEmittedDocument(t *testing.T) {
	source := `<fattura><numero>1</numero></fattura>`
	output := signXades(t, source, false)

	declared := extractDigest(t, output, 0)

	// The digest is taken over the canonical form, so the comparison must
	// canonicalise too: hashing the raw text would compare two different things.
	// The source fixture is already canonical (no whitespace between elements,
	// no comments), so canonical form equals the source here.
	digest := sha256.Sum256([]byte(source))
	computed := base64.StdEncoding.EncodeToString(digest[:])

	if declared != computed {
		t.Errorf("document digest = %s, recomputed = %s", declared, computed)
	}
}

// TestXadesEnvelopingReferencesItsOwnPayload checks the mode where the source
// document travels inside the signature.
func TestXadesEnvelopingReferencesItsOwnPayload(t *testing.T) {
	output := signXades(t, `<fattura><numero>1</numero></fattura>`, true)

	if !strings.Contains(output, `Id="trebaruna-payload-`) {
		t.Error("an enveloping signature must carry an Object with its payload id")
	}
	if !strings.Contains(output, `URI="#trebaruna-payload-`) {
		t.Error("an enveloping signature must reference its payload by id")
	}
	if strings.Contains(output, "enveloped-signature") {
		t.Error("an enveloping signature must not declare the enveloped transform")
	}
}

// TestXadesIncludesSigningCertificateV2 is required by EN 319 132-1.
func TestXadesIncludesSigningCertificateV2(t *testing.T) {
	output := signXades(t, `<fattura/>`, false)

	for _, required := range []string{"SigningCertificateV2", "SigningTime", "SignerCertificate"} {
		if required == "SignerCertificate" {
			continue
		}
		if !strings.Contains(output, required) {
			t.Errorf("the signature is missing %s", required)
		}
	}
	if !strings.Contains(output, "<ds:X509Certificate>") {
		t.Error("the signing certificate must travel inside the signature")
	}
}

// signXades runs the real adapter against a throwaway certificate.
func signXades(t *testing.T, document string, enveloping bool) string {
	t.Helper()

	fixture := newFixture(t)
	keyPEM := readFile(t, fixture.keyPath)
	certPEM := readFile(t, fixture.certPath)

	signer := buildPemSigner(t, keyPEM, certPEM)

	adapter := infrastructure.NewXadesSigner(nil)
	output, err := adapter.SignXades(t.Context(), buildXadesRequest(signer, []byte(document), enveloping))
	if err != nil {
		t.Fatalf("SignXades: %v", err)
	}
	return string(output)
}

// extractDigest returns the DigestValue of the nth reference.
func extractDigest(t *testing.T, output string, index int) string {
	t.Helper()

	marker := "<ds:DigestValue>"
	offset := 0
	for position := 0; position <= index; position++ {
		found := strings.Index(output[offset:], marker)
		if found < 0 {
			t.Fatalf("reference %d has no DigestValue", index)
		}
		offset += found + len(marker)
		if position == index {
			end := strings.Index(output[offset:], "</ds:DigestValue>")
			if end < 0 {
				t.Fatalf("DigestValue %d is not closed", index)
			}
			return output[offset : offset+end]
		}
	}
	return ""
}

// readFile reads a fixture file.
func readFile(t *testing.T, path string) []byte {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return content
}

// buildPemSigner creates a signer from a PEM certificate and key.
func buildPemSigner(t *testing.T, keyPEM, certPEM []byte) domain.Signer {
	t.Helper()

	bundle := append(append([]byte{}, certPEM...), keyPEM...)
	signer, err := domain.NewSigner("Test Signer", domain.FromPEM, domain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	return signer
}

// buildXadesRequest assembles the adapter request.
func buildXadesRequest(signer domain.Signer, content []byte, enveloping bool) application.XadesRequest {
	return application.XadesRequest{
		Content:   content,
		Signer:    signer,
		Level:     domain.BES,
		Packaging: packagingOf(enveloping),
	}
}

// TestXadesDeclaresTheFormatOfWhatItSigns: the XAdES baseline (EN 319 132-1,
// B-B) asks for a DataObjectFormat bound to the signed data reference.
func TestXadesDeclaresTheFormatOfWhatItSigns(t *testing.T) {
	enveloped := signXades(t, `<fattura/>`, false)
	format := regexp.MustCompile(`<xades:DataObjectFormat ObjectReference="#(trebaruna-reference-[0-9a-f]+)"><xades:MimeType>text/xml</xades:MimeType>`).FindStringSubmatch(enveloped)
	if format == nil {
		t.Fatal("an enveloped signature must declare that it signs text/xml")
	}
	if !strings.Contains(enveloped, `Id="`+format[1]+`"`) {
		t.Error("the format must point at a reference that exists")
	}

	// XML travels as XML inside the Object; other bytes in Base64, said so.
	enveloping := signXades(t, `<fattura/>`, true)
	if !strings.Contains(enveloping, `<xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat>`) {
		t.Error("an enveloping signature of XML declares text/xml")
	}
	binary := signXades(t, "%PDF-1.4\n%fixture\n", true)
	if !strings.Contains(binary, `<xades:MimeType>application/pdf</xades:MimeType><xades:Encoding>http://www.w3.org/2000/09/xmldsig#base64</xades:Encoding>`) {
		t.Error("an enveloping signature of a PDF carries Base64 and must say so")
	}
}

// TestXadesWritesECDSAAsXMLDSigExpects pins RFC 6931: an ECDSA SignatureValue
// is r||s at the curve's width, not the ASN.1 SEQUENCE crypto.Signer returns.
// The SEQUENCE verified with our own reader and was refused by signxml.
func TestXadesWritesECDSAAsXMLDSigExpects(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "MARIO ROSSI"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer := buildPemSigner(t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	output, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), buildXadesRequest(signer, []byte(`<fattura/>`), false))
	if err != nil {
		t.Fatalf("SignXades: %v", err)
	}

	opening := strings.Index(string(output), "<ds:SignatureValue")
	start := opening + strings.Index(string(output[opening:]), ">") + 1
	end := strings.Index(string(output), "</ds:SignatureValue>")
	value, err := base64.StdEncoding.DecodeString(string(output[start:end]))
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 64 {
		t.Fatalf("SignatureValue is %d bytes, want 64 (r||s on P-256)", len(value))
	}
}

// TestXadesKeepsWhatSurroundsTheRoot: a FatturaPA's stylesheet instruction
// and the comments outside the root were dropped from the signed file up to
// 0.30.1. They stay, and the document reference covers the instructions, as
// C14N says and xmlsec1 and Java's XML-Signature check.
func TestXadesKeepsWhatSurroundsTheRoot(t *testing.T) {
	source := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<?xml-stylesheet type=\"text/xsl\" href=\"fatturaPA_v1.2.xsl\"?>\n" +
		"<!-- copia di cortesia -->\n" +
		"<p:FatturaElettronica xmlns:p=\"http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2\"><Numero>7</Numero></p:FatturaElettronica>\n" +
		"<?after-root?>\n"
	output := signXades(t, source, false)

	stylesheet := strings.Index(output, `<?xml-stylesheet type="text/xsl" href="fatturaPA_v1.2.xsl"?>`)
	comment := strings.Index(output, "<!-- copia di cortesia -->")
	root := strings.Index(output, "<p:FatturaElettronica")
	after := strings.Index(output, "<?after-root?>")
	if stylesheet < 0 || comment < stylesheet || root < comment || after < root {
		t.Fatalf("the prolog and epilog must stay in place:\n%s", output)
	}
	if strings.Count(output, "<?xml version") != 1 {
		t.Error("one XML declaration")
	}

	if err := checkXML(t, output); err != nil {
		t.Errorf("the signature must verify: %v", err)
	}
	withoutStylesheet := strings.Replace(output, `<?xml-stylesheet type="text/xsl" href="fatturaPA_v1.2.xsl"?>`, "", 1)
	if err := checkXML(t, withoutStylesheet); !errors.Is(err, xmldsig.ErrModified) {
		t.Errorf("the stylesheet instruction is signed: %v", err)
	}
}

// TestXadesDeclaresADocumentThatStartsWithAnInstruction: <?xml-stylesheet
// is not a declaration, so one is still added.
func TestXadesDeclaresADocumentThatStartsWithAnInstruction(t *testing.T) {
	output := signXades(t, "<?xml-stylesheet href=\"x.xsl\"?>\n<fattura/>", false)
	if !strings.HasPrefix(output, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Errorf("no declaration added:\n%s", output)
	}
	if err := checkXML(t, output); err != nil {
		t.Error(err)
	}
}

// checkXML runs the complete XML-Signature check on a signed document.
func checkXML(t *testing.T, signed string) error {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromString(signed); err != nil {
		t.Fatal(err)
	}
	var signature *etree.Element
	for _, element := range document.Root().ChildElements() {
		if element.Tag == "Signature" {
			signature = element
		}
	}
	if signature == nil {
		t.Fatal("no signature")
	}
	certificateElement := signature.FindElement(".//X509Certificate")
	der, err := base64.StdEncoding.DecodeString(certificateElement.Text())
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return xmldsig.Check(document, signature, certificate.PublicKey, nil)
}

// TestEachXadesSignatureHasItsOwnIds: signing a signed document again must
// not repeat an Id, or the new references find the old elements.
func TestEachXadesSignatureHasItsOwnIds(t *testing.T) {
	once := signXades(t, `<acta><punto>1</punto></acta>`, false)
	twice := signXades(t, once, false)
	ids := regexp.MustCompile(` Id="([^"]+)"`).FindAllStringSubmatch(twice, -1)
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id[1]] {
			t.Errorf("Id %s appears twice", id[1])
		}
		seen[id[1]] = true
	}
	if len(ids) < 6 {
		t.Errorf("only %d Ids in two signatures", len(ids))
	}
}

// TestASecondXadesLeavesTheFirstIntact: each enveloped signature excludes
// every signature (AutoFirma's XPath filter), so signing a signed document
// again does not break the first signature.
func TestASecondXadesLeavesTheFirstIntact(t *testing.T) {
	twice := signXades(t, signXades(t, `<acta><punto>1</punto></acta>`, false), false)
	document := etree.NewDocument()
	if err := document.ReadFromString(twice); err != nil {
		t.Fatal(err)
	}
	signatures := xmldsig.Signatures(document)
	if len(signatures) != 2 {
		t.Fatalf("%d signatures, want 2", len(signatures))
	}
	for index, signature := range signatures {
		der, err := base64.StdEncoding.DecodeString(signature.FindElement(".//X509Certificate").Text())
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := xmldsig.Check(document, signature, certificate.PublicKey, nil); err != nil {
			t.Errorf("signature %d: %v", index+1, err)
		}
	}
}

// packagingOf is the XML packaging an enveloping flag stands for.
func packagingOf(enveloping bool) domain.XMLPackaging {
	if enveloping {
		return domain.XMLEnveloping
	}
	return domain.XMLEnveloped
}
