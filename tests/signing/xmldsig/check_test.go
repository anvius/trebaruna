package xmldsig_test

// The XML-Signature check is judged against signatures made by signxml and
// xmlsec1 (testdata/PROVENANCE.md), each accepted by xmlsec1 first: what they
// sign must verify, and any change to what they sign must not.

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/publickey"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

func publicKey(t *testing.T, name string) crypto.PublicKey {
	t.Helper()
	block, _ := pem.Decode(read(t, name))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return publickey.Of(certificate)
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// check parses a fixture, after an optional change, and checks its signature.
func check(t *testing.T, name string, change func(string) string, resolve xmldsig.Resolver) error {
	t.Helper()
	content := string(read(t, name))
	if change != nil {
		changed := change(content)
		if changed == content {
			t.Fatalf("%s: the change did not apply", name)
		}
		content = changed
	}
	document := etree.NewDocument()
	if err := document.ReadFromString(content); err != nil {
		t.Fatal(err)
	}
	key := publicKey(t, "rsa.pem")
	switch {
	case strings.Contains(name, "pss"):
		key = publicKey(t, "pss.pem")
	case strings.Contains(name, "ecdsa-sha3"):
		key = publicKey(t, "ec-sha3.pem")
	case strings.Contains(name, "ecdsa"):
		key = publicKey(t, "ec.pem")
	}
	return xmldsig.Check(document, findSignature(document.Root()), key, resolve)
}

func findSignature(element *etree.Element) *etree.Element {
	if element.Tag == "Signature" && element.NamespaceURI() == xmldsig.Namespace {
		return element
	}
	for _, child := range element.ChildElements() {
		if found := findSignature(child); found != nil {
			return found
		}
	}
	return nil
}

func replace(old, new string) func(string) string {
	return func(content string) string { return strings.Replace(content, old, new, 1) }
}

var sameDocument = []string{
	"signxml-enveloped-c14n11.xml",
	"signxml-enveloped-exc.xml",
	"signxml-enveloping-ecdsa.xml",
	"signxml-xades-enveloped.xml",
	"xmlsec-sha1-xpath.xml",
	"xmlsec-detached-base64.xml",
	"xmlsec-detached-xml.xml",
	"xmlsec-pss-sha256.xml",
	"xmlsec-pss-sha3.xml",
	"xmlsec-ecdsa-sha3.xml",
}

// TestSignaturesFromOtherImplementationsVerify.
func TestSignaturesFromOtherImplementationsVerify(t *testing.T) {
	for _, name := range sameDocument {
		if err := check(t, name, nil, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestAnyChangeToWhatIsSignedIsCaught, the signed properties and the
// prolog's processing instructions included.
func TestAnyChangeToWhatIsSignedIsCaught(t *testing.T) {
	changes := []struct {
		name   string
		change func(string) string
	}{
		{"signxml-enveloped-c14n11.xml", replace("Licencia de obra", "Licencia de obro")},
		{"signxml-enveloped-exc.xml", replace("120.50", "120.51")},
		{"signxml-enveloping-ecdsa.xml", replace("Licencia", "Licencio")},
		{"signxml-xades-enveloped.xml", replace("<xades:SigningTime>2026", "<xades:SigningTime>2025")},
		{"xmlsec-sha1-xpath.xml", replace("<Numero>7</Numero>", "<Numero>8</Numero>")},
		{"xmlsec-sha1-xpath.xml", replace(`<?xml-stylesheet type="text/xsl" href="fatturaPA_v1.2.xsl"?>`, "")},
		{"xmlsec-detached-base64.xml", replace("JVBERi0xLjQgZml4dHVyZSBkb2N1bW", "JVBERi0xLjUgZml4dHVyZSBkb2N1bW")},
		{"xmlsec-detached-xml.xml", replace("Licencia", "Licencio")},
		{"xmlsec-detached-xml.xml", replace(`MimeType="text/xml"`, `MimeType="text/plain"`)},
		{"xmlsec-pss-sha256.xml", replace("Prestador cualificado", "Prestador falso")},
		{"xmlsec-pss-sha3.xml", replace("Prestador cualificado", "Prestador falso")},
		{"xmlsec-ecdsa-sha3.xml", replace("Prestador cualificado", "Prestador falso")},
	}
	for index, entry := range changes {
		if err := check(t, entry.name, entry.change, nil); !errors.Is(err, xmldsig.ErrModified) {
			t.Errorf("change %d to %s: %v, want ErrModified", index, entry.name, err)
		}
	}
}

// TestCommentsAreNotSigned: a same-document reference drops them.
func TestCommentsAreNotSigned(t *testing.T) {
	err := check(t, "xmlsec-sha1-xpath.xml", func(content string) string {
		content = strings.Replace(content, "<!-- nota -->", "<!-- otra nota -->", 1)
		return strings.Replace(content, "<!-- generated for trebaruna's tests -->", "<!-- copia -->", 1)
	}, nil)
	if err != nil {
		t.Errorf("a changed comment: %v", err)
	}
}

// TestADetachedReferenceNeedsItsDocument: missing is not modified.
func TestADetachedReferenceNeedsItsDocument(t *testing.T) {
	if err := check(t, "xmlsec-external.xml", nil, nil); !errors.Is(err, xmldsig.ErrContentMissing) {
		t.Errorf("without the document: %v", err)
	}
	beside := func(uri string) ([]byte, error) {
		if uri != "documento.txt" {
			return nil, fmt.Errorf("%w: %s", xmldsig.ErrContentMissing, uri)
		}
		return read(t, "documento.txt"), nil
	}
	if err := check(t, "xmlsec-external.xml", nil, beside); err != nil {
		t.Errorf("with the document: %v", err)
	}
	other := func(string) ([]byte, error) { return []byte("otro documento\n"), nil }
	if err := check(t, "xmlsec-external.xml", nil, other); !errors.Is(err, xmldsig.ErrModified) {
		t.Errorf("with another document: %v", err)
	}
}

// TestWhatTrebarunaCannotEvaluateIsNotCalledModified.
func TestWhatTrebarunaCannotEvaluateIsNotCalledModified(t *testing.T) {
	if err := check(t, "xmlsec-xpath-other.xml", nil, nil); !errors.Is(err, xmldsig.ErrUnverifiable) {
		t.Errorf("another XPath expression: %v, want ErrUnverifiable", err)
	}
}

// TestASecondElementWithTheSignedIdIsRefused: a wrapping attack puts the
// signed element somewhere else and another one where readers look.
func TestASecondElementWithTheSignedIdIsRefused(t *testing.T) {
	err := check(t, "xmlsec-detached-base64.xml", replace(`<AFIRMA Id="AFIRMA-Root-1">`,
		`<AFIRMA Id="AFIRMA-Root-1"><CONTENT Id="CONTENT-1">b3Rybw==</CONTENT>`), nil)
	if !errors.Is(err, xmldsig.ErrModified) {
		t.Errorf("two elements with the signed Id: %v", err)
	}
}

// TestTheCanonicalDocumentKeepsItsInstructions (C14N 1.0, 2.1): one line
// each, before or after the root; no declaration, no document type, comments
// only when kept.
func TestTheCanonicalDocumentKeepsItsInstructions(t *testing.T) {
	document := etree.NewDocument()
	source := `<?xml version="1.0"?>` + "\n" + `<!DOCTYPE a>` + "\n" + `<?style href="x"?>` + "\n" +
		`<!-- before -->` + "\n" + `<a  b="1"/>` + "\n" + `<?after?>`
	if err := document.ReadFromString(source); err != nil {
		t.Fatal(err)
	}
	canonical, err := xmldsig.CanonicalizeDocument(document, xmldsig.C14N10, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := "<?style href=\"x\"?>\n<a b=\"1\"></a>\n<?after?>"; string(canonical) != want {
		t.Errorf("canonical form %q, want %q", canonical, want)
	}
	withComments, err := xmldsig.CanonicalizeDocument(document, xmldsig.C14N10Comments, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(withComments), "<!-- before -->\n<a") {
		t.Errorf("with comments %q", withComments)
	}
}

// TestAutoFirmasEnvelopedOrderVerifies: enveloped, C14N, then the XPath
// filter on the canonical octets, as AutoFirma writes every enveloped XAdES.
func TestAutoFirmasEnvelopedOrderVerifies(t *testing.T) {
	if err := check(t, "xmlsec-autofirma-order.xml", nil, nil); err != nil {
		t.Errorf("AutoFirma's order: %v", err)
	}
	if err := check(t, "xmlsec-autofirma-order.xml", replace("Subvención", "Subvencion"), nil); !errors.Is(err, xmldsig.ErrModified) {
		t.Errorf("a changed document: %v", err)
	}
}

// TestEverySignatureOfACosignedDocumentHolds: each excludes all signatures,
// so adding the second did not break the first.
func TestEverySignatureOfACosignedDocumentHolds(t *testing.T) {
	document := etree.NewDocument()
	if err := document.ReadFromBytes(read(t, "xmlsec-cosigned.xml")); err != nil {
		t.Fatal(err)
	}
	keys := map[string]crypto.PublicKey{"Signature-A": publicKey(t, "rsa.pem"), "Signature-B": publicKey(t, "ec.pem")}
	signatures := xmldsig.Signatures(document)
	if len(signatures) != 2 {
		t.Fatalf("%d signatures found, want 2", len(signatures))
	}
	for _, signature := range signatures {
		id := signature.SelectAttrValue("Id", "")
		if err := xmldsig.Check(document, signature, keys[id], nil); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
}
