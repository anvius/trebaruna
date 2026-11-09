package integration_test

// A valid XML signature that references one element by Id leaves the rest
// of the document unsigned; the report names that rest.

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func TestAnXMLSignatureOverOnePartNamesTheRest(t *testing.T) {
	fixture := newFixture(t)
	keyBlock, _ := pem.Decode(readFile(t, fixture.keyPath))
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, _ := pem.Decode(readFile(t, fixture.certPath))

	document := etree.NewDocument()
	if err := document.ReadFromString(`<root><signed Id="part">ok</signed><extra>not signed</extra><more><x/></more></root>`); err != nil {
		t.Fatal(err)
	}
	signature := etree.NewDocument()
	signature.ReadFromString(`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + xmldsig.C14N10 + `"/>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
		`<ds:Reference URI="#part"><ds:Transforms><ds:Transform Algorithm="` + xmldsig.C14N10 + `"/></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>` +
		`</ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(certificateBlock.Bytes) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`)
	document.Root().AddChild(signature.Root())
	serialised, _ := document.WriteToBytes()
	document = etree.NewDocument()
	if err := document.ReadFromBytes(serialised); err != nil {
		t.Fatal(err)
	}

	element := document.Root().ChildElements()[3]
	reference := element.FindElement("./SignedInfo/Reference")
	data, err := xmldsig.ReferenceData(document, element, reference, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	reference.SelectElement("DigestValue").SetText(base64.StdEncoding.EncodeToString(digest[:]))
	canonical, err := xmldsig.Canonicalize(element.SelectElement("SignedInfo"), xmldsig.C14N10, "")
	if err != nil {
		t.Fatal(err)
	}
	hashed := sha256.Sum256(canonical)
	value, err := key.(crypto.Signer).Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	element.SelectElement("SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))

	path := filepath.Join(fixture.directory, "partial.xml")
	written, _ := document.WriteToBytes()
	os.WriteFile(path, written, 0o600)
	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil || len(reports) != 1 {
		t.Fatalf("%v %v", reports, err)
	}
	report := reports[0]
	var detail string
	for _, finding := range report.Findings {
		if finding.Code == "content.partly_signed" {
			detail = finding.Detail
		}
	}
	if report.Integrity != verificationdomain.StatusGood || detail != "/root/extra, /root/more" {
		t.Errorf("integrity %s, unsigned parts %q, findings %+v", report.Integrity, detail, report.Findings)
	}
}
