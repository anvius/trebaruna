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
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// verifyXML returns the name of each signature in document order, failing
// on any that is not intact or does not say whom it counter-signs.
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
	var fields []string
	for _, report := range reports {
		if report.Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %s %+v", report.FieldName, report.Integrity, report.Findings)
		}
		for _, finding := range report.Findings {
			if finding.Code == "content.partly_signed" {
				t.Errorf("%s is read as a partial signature, not a counter-signature", report.FieldName)
			}
			// Counter-signing keeps every timestamp: a timestamped
			// signature's value already has the Id that names it.
			if finding.Status == verificationdomain.StatusBad {
				t.Errorf("%s: %s %s", report.FieldName, finding.Code, finding.Detail)
			}
		}
		// A counter-signature is named after the one it signs, as CMS's are,
		// and says which one that is.
		signs := ""
		if cut := strings.LastIndex(report.FieldName, " › countersignature "); cut > 0 {
			signs = report.FieldName[:cut]
		}
		if report.Countersigns != signs {
			t.Errorf("%s counter-signs %q", report.FieldName, report.Countersigns)
		}
		fields = append(fields, report.FieldName)
	}
	return fields
}

// TestATimestampedValueWithoutAnIdIsNotCounterSigned: a counter-signature
// names the value it signs by its Id. trebaruna gives every value one; a
// signature from elsewhere without it takes one when nothing seals the
// value, and is refused when a timestamp does, which the Id would break.
func TestATimestampedValueWithoutAnIdIsNotCounterSigned(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	authority := newLocalTSA(t)
	withoutID := regexp.MustCompile(`<ds:SignatureValue Id="[^"]+">`)

	plain := []byte(signXades(t, `<solicitud><asunto>Licencia</asunto></solicitud>`, false))
	if !withoutID.Match(plain) {
		t.Fatal("a trebaruna signature value has its Id from the start")
	}
	plain = withoutID.ReplaceAll(plain, []byte("<ds:SignatureValue>"))
	if _, err := countersignXML(t, signer, authority, plain, "leaves", domain.BES); err != nil {
		t.Errorf("a value nothing seals takes an Id: %v", err)
	}

	request := buildXadesRequest(signer, []byte(`<solicitud><asunto>Licencia</asunto></solicitud>`), false)
	request.Level, request.TimestampURL = domain.T, "http://tsa.example.invalid"
	stamped, err := infrastructure.NewXadesSigner(authority).SignXades(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	stamped = withoutID.ReplaceAll(stamped, []byte("<ds:SignatureValue>"))
	if _, err := countersignXML(t, signer, authority, stamped, "leaves", domain.BES); err == nil || !strings.Contains(err.Error(), "break that timestamp") {
		t.Errorf("a timestamped value without an Id: %v", err)
	}

	// An archive timestamp seals the value too, signature timestamp or not.
	_, archiving := ltaFixture(t)
	request = buildXadesRequest(archiving, []byte(`<solicitud><asunto>Licencia</asunto></solicitud>`), false)
	request.Level, request.TimestampURL, request.EmbedRevocation = domain.LTA, "http://tsa.example.invalid", true
	archived, err := infrastructure.NewXadesSigner(authority).SignXades(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	archived = regexp.MustCompile(`(?s)<xades:SignatureTimeStamp.*?</xades:SignatureTimeStamp>`).ReplaceAll(archived, nil)
	archived = withoutID.ReplaceAll(archived, []byte("<ds:SignatureValue>"))
	if !strings.Contains(string(archived), "ArchiveTimeStamp") || strings.Contains(string(archived), "SignatureTimeStamp") {
		t.Fatal("the fixture is an archive timestamp without a signature timestamp")
	}
	if _, err := countersignXML(t, signer, authority, archived, "leaves", domain.BES); err == nil || !strings.Contains(err.Error(), "break that timestamp") {
		t.Errorf("an archived value without an Id: %v", err)
	}
}

// timestampJudgements says, for each signature, what its timestamp was
// found to be: timestamp.bound, timestamp.invalid, or none.
func timestampJudgements(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signed.xml")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil {
		t.Fatal(err)
	}
	var judged []string
	for _, report := range reports {
		judgement := "none"
		for _, finding := range report.Findings {
			if finding.Code == "timestamp.bound" || finding.Code == "timestamp.invalid" {
				judgement = finding.Code
			}
		}
		judged = append(judged, report.FieldName+": "+judgement)
	}
	return strings.Join(judged, "|")
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
	if got := verifyXML(t, once); strings.Join(got, "|") != "XMLSignature|XMLSignature › countersignature 1" {
		t.Errorf("counter-signed: %q", got)
	}
	if strings.Count(string(once), "<xades:SignatureTimeStamp") != 1 || !strings.Contains(string(once), "01903#CountersignedSignature") {
		t.Error("the counter-signature is XAdES-T and names what it signs")
	}
	// The counter-signature's timestamp is its own: the signature it signs,
	// which has none, is not judged by it.
	if judged := timestampJudgements(t, once); judged != "XMLSignature: none|XMLSignature › countersignature 1: timestamp.bound" {
		t.Errorf("timestamps: %q", judged)
	}

	nested, err := countersignXML(t, signer, authority, once, "leaves", domain.BES)
	if err != nil {
		t.Fatal(err)
	}
	if got := verifyXML(t, nested); strings.Join(got, "|") != "XMLSignature|XMLSignature › countersignature 1|XMLSignature › countersignature 1 › countersignature 1" {
		t.Errorf("the leaves of a counter-signed document: %q", got)
	}
	all, err := countersignXML(t, signer, authority, once, "all", domain.BES)
	if err != nil {
		t.Fatal(err)
	}
	if got := verifyXML(t, all); strings.Join(got, "|") != "XMLSignature|XMLSignature › countersignature 1|XMLSignature › countersignature 1 › countersignature 1|XMLSignature › countersignature 2" {
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
