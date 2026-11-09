package integration_test

// EN 319 132-1, 5.5.2.2: the archive timestamp's input starts with the
// result of processing every ds:Reference of SignedInfo, the document
// included. Up to 0.30.4 the enveloped document reference (URI="") was
// skipped, so the token covered everything but the document and no other
// validator could reproduce its imprint. The input is rebuilt here from the
// file, step by step, with canonical forms only.

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

func TestTheArchiveTimestampCoversTheSignedDocument(t *testing.T) {
	tsa := newLocalTSA(t)
	_, signer := ltaFixture(t)
	source := "<?xml version=\"1.0\"?>\n<?xml-stylesheet href=\"f.xsl\"?>\n<fattura><n>3</n></fattura>"
	request := buildXadesRequest(signer, []byte(source), false)
	request.Level = domain.LTA
	request.TimestampURL = "http://tsa.example.invalid"
	request.EmbedRevocation = true
	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	signature := xmldsig.Signatures(document)[0]
	canonical := func(element *etree.Element) []byte {
		t.Helper()
		out, err := xmldsig.Canonicalize(element, xmldsig.C14N10, "")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	var input []byte

	// 1. Each reference, processed. The document: every signature left out,
	// canonicalised as a document node (its stylesheet instruction included).
	withoutSignatures := document.Copy()
	for _, element := range xmldsig.Signatures(withoutSignatures) {
		element.Parent().RemoveChild(element)
	}
	documentNode, err := xmldsig.CanonicalizeDocument(withoutSignatures, xmldsig.C14N10, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(documentNode), `<?xml-stylesheet href="f.xsl"?>`) {
		t.Fatalf("document node %q", documentNode)
	}
	input = append(input, documentNode...)
	properties := signature.FindElement(".//SignedProperties")
	input = append(input, canonical(properties)...)

	// 2. SignedInfo, SignatureValue, KeyInfo.
	for _, name := range []string{"SignedInfo", "SignatureValue", "KeyInfo"} {
		input = append(input, canonical(signature.SelectElement(name))...)
	}
	// 3. The unsigned signature properties written before the archive token.
	for _, property := range signature.FindElement(".//UnsignedSignatureProperties").ChildElements() {
		if property.Tag != "ArchiveTimeStamp" {
			input = append(input, canonical(property)...)
		}
	}
	// 4. The other ds:Object elements: none in an enveloped signature.

	expected := sha256.Sum256(input)
	if string(expected[:]) != string(tsa.imprint) {
		t.Errorf("the archive token's imprint is not the digest of EN 319 132-1's input\n  expected %x\n  token    %x", expected, tsa.imprint)
	}
}

// TestADetachedXadesCanBeArchived: the archive input includes the document
// beside the signature, which the signer has.
func TestADetachedXadesCanBeArchived(t *testing.T) {
	tsa := newLocalTSA(t)
	_, signer := ltaFixture(t)
	request := buildXadesRequest(signer, []byte("%PDF-1.4\n%archivo\n"), false)
	request.Packaging = domain.XMLDetached
	request.DocumentName = "archivo.pdf"
	request.Level = domain.LTA
	request.TimestampURL = "http://tsa.example.invalid"
	request.EmbedRevocation = true
	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.Contains(string(signed), "ArchiveTimeStamp") || tsa.requests != 2 {
		t.Errorf("a detached LTA signature carries both timestamps (%d requests)", tsa.requests)
	}
}
