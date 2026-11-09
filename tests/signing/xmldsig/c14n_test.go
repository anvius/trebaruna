package xmldsig_test

// Canonical forms judged against libxml2's (xmllint --c14n, --c14n11,
// --exc-c14n), the library xmlsec builds on. goxmldsig, used before, sorted
// prefixed attributes by local name: LibreOffice's content.xml, and any
// element with xml:lang and xsi: attributes, came out wrong.

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

var corpus = []string{"odf-content.xml", "odf-styles.xml", "attributes.xml", "namespaces.xml"}

func canonicalOf(t *testing.T, name, algorithm string) string {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromFile(filepath.Join("testdata", "c14n", name)); err != nil {
		t.Fatal(err)
	}
	canonical, err := xmldsig.CanonicalizeDocument(document, algorithm, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

// TestCanonicalFormsMatchLibxml2 for every document and algorithm.
func TestCanonicalFormsMatchLibxml2(t *testing.T) {
	if _, err := exec.LookPath("xmllint"); err != nil {
		t.Skip("xmllint is not installed")
	}
	algorithms := map[string]string{
		"--c14n":     xmldsig.C14N10Comments,
		"--c14n11":   xmldsig.C14N11Comments,
		"--exc-c14n": xmldsig.ExcC14NComments,
	}
	for _, name := range corpus {
		for flag, algorithm := range algorithms {
			reference, err := exec.Command("xmllint", flag, filepath.Join("testdata", "c14n", name)).Output()
			if err != nil {
				t.Fatalf("xmllint %s %s: %v", flag, name, err)
			}
			if ours := canonicalOf(t, name, algorithm); ours != string(reference) {
				t.Errorf("%s %s differs from libxml2 at byte %d:\n ours %q\n  ref %q", flag, name,
					firstDifference(ours, string(reference)), around(ours, string(reference)), around(string(reference), ours))
			}
		}
	}
}

// TestAttributesSortByNamespaceURI without any external tool: unqualified
// first, then by URI, so xsi: (http://www.w3.org/2001/…) precedes xml:
// (http://www.w3.org/XML/…) and urn: comes last.
func TestAttributesSortByNamespaceURI(t *testing.T) {
	canonical := canonicalOf(t, "attributes.xml", xmldsig.C14N10)
	expected := `<f:Factura xmlns:f="urn:factura" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="1.0" xsi:schemaLocation="urn:factura factura.xsd" xml:lang="es">`
	if !strings.HasPrefix(canonical, expected) {
		t.Errorf("root: %.220s", canonical)
	}
	if !strings.Contains(canonical, `<f:Atributos cita="dijo &quot;hola&quot;" texto="a&#x9;b&#xA;c&#xD;d"></f:Atributos>`) {
		t.Errorf("attribute escaping: %s", canonical)
	}
	if strings.Contains(canonical, "comentario") {
		t.Error("comments are dropped without #WithComments")
	}
}

func firstDifference(a, b string) int {
	for index := 0; index < len(a) && index < len(b); index++ {
		if a[index] != b[index] {
			return index
		}
	}
	return min(len(a), len(b))
}

func around(text, other string) string {
	index := firstDifference(text, other)
	return text[max(0, index-60):min(len(text), index+60)]
}
