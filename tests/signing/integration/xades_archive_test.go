package integration_test

// EN 319 132-1, 5.5.2.2: the archive timestamp's input starts with the
// result of processing every ds:Reference of SignedInfo, the document
// included. Up to 0.47.4 the enveloped document reference (URI="") was
// skipped, so the token covered everything but the document and no other
// validator could reproduce its imprint. The input is rebuilt here from the
// file, step by step, with canonical forms only.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
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

// TestEveryArchiveTimestampIsChecked: a renewed XAdES-A carries a second
// ArchiveTimeStamp over everything before it, the first included. Each is
// checked: two that hold are two findings; a second that covers something
// else says so, where only the first used to be read.
func TestEveryArchiveTimestampIsChecked(t *testing.T) {
	tsa := newLocalTSA(t)
	_, signer := ltaFixture(t)
	request := buildXadesRequest(signer, []byte("<fattura><n>3</n></fattura>"), false)
	request.Level, request.TimestampURL, request.EmbedRevocation = domain.LTA, "http://tsa.example.invalid", true
	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	for name, check := range map[string]struct {
		covers   func(input []byte) []byte
		archival int
		unbound  int
	}{
		"renewed":             {func(input []byte) []byte { return input }, 2, 0},
		"over something else": {func([]byte) []byte { return []byte("otro") }, 1, 1},
	} {
		renewed := renewArchive(t, tsa, signed, check.covers)
		path := filepath.Join(t.TempDir(), "renewed.xml")
		if err := os.WriteFile(path, renewed, 0o600); err != nil {
			t.Fatal(err)
		}
		reports, err := verificationinfra.NewXadesVerifier().Extract(path)
		if err != nil || len(reports) != 1 {
			t.Fatalf("%s: %v %v", name, reports, err)
		}
		archival, unbound := 0, 0
		for _, finding := range reports[0].Findings {
			switch finding.Code {
			case "timestamp.archival":
				archival++
			case "timestamp.archive_unbound":
				unbound++
			}
		}
		if archival != check.archival || unbound != check.unbound || reports[0].Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %d archival, %d unbound, integrity %s: %+v", name, archival, unbound, reports[0].Integrity, reports[0].Findings)
		}
	}
}

// TestAnArchiveTimestampIsNoSignatureTimestamp: both hold their token in an
// EncapsulatedTimeStamp; a signature without its SignatureTimeStamp is not
// judged by its archive timestamp's token as if it were one.
func TestAnArchiveTimestampIsNoSignatureTimestamp(t *testing.T) {
	tsa := newLocalTSA(t)
	_, signer := ltaFixture(t)
	request := buildXadesRequest(signer, []byte("<fattura><n>3</n></fattura>"), false)
	request.Level, request.TimestampURL, request.EmbedRevocation = domain.LTA, "http://tsa.example.invalid", true
	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	stamp := document.FindElement("//SignatureTimeStamp")
	stamp.Parent().RemoveChild(stamp)
	without, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "without.xml")
	if err := os.WriteFile(path, without, 0o600); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil || len(reports) != 1 {
		t.Fatalf("%v %v", reports, err)
	}
	for _, finding := range reports[0].Findings {
		if finding.Code == "timestamp.invalid" || finding.Code == "timestamp.bound" {
			t.Errorf("the archive token was judged as a signature timestamp: %s", finding.Code)
		}
	}
	if reports[0].Timestamped {
		t.Error("a signature without its SignatureTimeStamp is not timestamped")
	}
}

// renewArchive adds a second ArchiveTimeStamp after the first, its token
// over what covers makes of the input EN 319 132-1 gives it.
func renewArchive(t *testing.T, tsa *localTSA, signed []byte, covers func([]byte) []byte) []byte {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	first := document.FindElement("//ArchiveTimeStamp")
	if first == nil {
		t.Fatal("no archive timestamp to renew")
	}
	second := first.Copy()
	first.Parent().InsertChildAt(first.Index()+1, second)
	// Measured on the tree as it is read back, as the signer measures it.
	written, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	document = etree.NewDocument()
	if err := document.ReadFromBytes(written); err != nil {
		t.Fatal(err)
	}
	second = document.FindElements("//ArchiveTimeStamp")[1]
	algorithm := second.SelectElement("CanonicalizationMethod").SelectAttrValue("Algorithm", xmldsig.C14N10)
	input, err := xmldsig.ArchiveTimeStampInput(document, xmldsig.Signatures(document)[0], nil, algorithm, second)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(covers(input))
	response, err := tsa.Token(context.Background(), digest[:], "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	token, err := cms.ExtractToken(response)
	if err != nil {
		t.Fatal(err)
	}
	second.SelectElement("EncapsulatedTimeStamp").SetText(base64.StdEncoding.EncodeToString(token))
	renewed, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return renewed
}
