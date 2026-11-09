package integration_test

// XAdES counter-signatures inside the document: a XAdES signature over
// another signature's SignatureValue, in its UnsignedSignatureProperties as
// xades:CounterSignature. The same code's output was judged by hand with
// xmlsec1 1.3.9, every signature by its Id ("Verification status: OK"),
// on a counter-signed, a twice counter-signed and a co-signed document.

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// verifyXML returns, for each signature in document order, whom it
// counter-signs, failing on any that is not intact.
func verifyXML(t *testing.T, content []byte) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signed.xml")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil {
		t.Fatal(err)
	}
	var countersigns []string
	for _, report := range reports {
		if report.Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %s %+v", report.FieldName, report.Integrity, report.Findings)
		}
		for _, finding := range report.Findings {
			if finding.Code == "content.partly_signed" {
				t.Errorf("%s is read as a partial signature, not a counter-signature", report.FieldName)
			}
		}
		countersigns = append(countersigns, report.Countersigns)
	}
	return countersigns
}

func countersignXML(t *testing.T, signer domain.Signer, authority *localTSA, content []byte, scope string, level domain.Level) ([]byte, error) {
	t.Helper()
	request := buildXadesRequest(signer, content, false)
	request.Countersign, request.Level, request.TimestampURL = scope, level, "http://tsa.example.invalid"
	return infrastructure.NewXadesSigner(authority).SignXades(t.Context(), request)
}

func TestXadesSignaturesAreCounterSignedInside(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	authority := newLocalTSA(t)
	signed := []byte(signXades(t, `<solicitud><asunto>Licencia</asunto></solicitud>`, false))

	once, err := countersignXML(t, signer, authority, signed, "leaves", domain.T)
	if err != nil {
		t.Fatal(err)
	}
	if got := verifyXML(t, once); strings.Join(got, "|") != "|XMLSignature #1" {
		t.Errorf("counter-signed: %q", got)
	}
	if strings.Count(string(once), "<xades:SignatureTimeStamp") != 1 || !strings.Contains(string(once), "01903#CountersignedSignature") {
		t.Error("the counter-signature is XAdES-T and names what it signs")
	}

	nested, err := countersignXML(t, signer, authority, once, "leaves", domain.BES)
	if err != nil {
		t.Fatal(err)
	}
	if got := verifyXML(t, nested); strings.Join(got, "|") != "|XMLSignature #1|XMLSignature #2" {
		t.Errorf("the leaves of a counter-signed document: %q", got)
	}
	all, err := countersignXML(t, signer, authority, once, "all", domain.BES)
	if err != nil {
		t.Fatal(err)
	}
	if got := verifyXML(t, all); strings.Join(got, "|") != "|XMLSignature #1|XMLSignature #2|XMLSignature #1" {
		t.Errorf("every signature: %q", got)
	}

	for name, attempt := range map[string]func() error{
		"level LT": func() error {
			_, err := countersignXML(t, signer, authority, signed, "leaves", domain.LT)
			return err
		},
		"a document without signatures": func() error {
			_, err := countersignXML(t, signer, authority, []byte(`<solicitud/>`), "leaves", domain.BES)
			return err
		},
	} {
		if attempt() == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

// TestACounterSignatureThatWouldBreakASignatureIsNotWritten: a second
// signature whose enveloped transform removes only itself covers the
// first, so counter-signing the first would break it.
func TestACounterSignatureThatWouldBreakASignatureIsNotWritten(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	signed := signXades(t, `<solicitud><asunto>Licencia</asunto></solicitud>`, false)

	document := etree.NewDocument()
	if err := document.ReadFromString(signed); err != nil {
		t.Fatal(err)
	}
	certificateBlock, _ := pem.Decode(readFile(t, fixture.certPath))
	outer := etree.NewDocument()
	outer.ReadFromString(`<ds:Signature xmlns:ds="` + xmldsig.Namespace + `" Id="outer"><ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + xmldsig.C14N10 + `"/>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
		`<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="` + xmldsig.EnvelopedSignature + `"/></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>` +
		`</ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(certificateBlock.Bytes) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`)
	document.Root().AddChild(outer.Root())
	serialised, _ := document.WriteToBytes()
	document = etree.NewDocument()
	document.ReadFromBytes(serialised)
	element := document.Root().FindElement("./Signature[@Id='outer']")
	reference := element.FindElement("./SignedInfo/Reference")
	data, err := xmldsig.ReferenceData(document, element, reference, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	reference.SelectElement("DigestValue").SetText(base64.StdEncoding.EncodeToString(digest[:]))
	canonical, _ := xmldsig.Canonicalize(element.SelectElement("SignedInfo"), xmldsig.C14N10, "")
	hashed := sha256.Sum256(canonical)
	keyBlock, _ := pem.Decode(readFile(t, fixture.keyPath))
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	value, err := key.(crypto.Signer).Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	element.SelectElement("SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))
	twoSigned, _ := document.WriteToBytes()
	verifyXML(t, twoSigned)

	request := buildXadesRequest(signer, twoSigned, false)
	request.Countersign = "leaves"
	if _, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), request); err == nil || !strings.Contains(err.Error(), "would break") {
		t.Errorf("%v", err)
	}
}
