package signature_test

// A trust list is authenticated only when its own signature, made by the
// certificate the EU list of the lists publishes for the territory, verifies
// and signs the whole list. Each case changes one of those conditions. The
// lists the EU list of the lists pointed at on 9 November 2026 were also
// synced: of the 30 that could be fetched, all but Germany's, signed with
// RSA-PSS, authenticate.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	trustinfra "codeberg.org/simplicer/trebaruna/src/trust/infrastructure"
)

const list = `<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#" Id="TSL-1">` +
	`<tsl:SchemeInformation Id="scheme"><tsl:SchemeTerritory>XX</tsl:SchemeTerritory></tsl:SchemeInformation>` +
	`<tsl:TrustServiceProviderList><tsl:TrustServiceProvider><tsl:TSPInformation>` +
	`<tsl:TSPName>Real CA</tsl:TSPName></tsl:TSPInformation></tsl:TrustServiceProvider></tsl:TrustServiceProviderList>` +
	`</tsl:TrustServiceStatusList>`

// operator is a scheme operator: a key and its certificate.
type operator struct {
	key         *rsa.PrivateKey
	certificate *x509.Certificate
}

func newOperator(t *testing.T, name string) operator {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name, Country: []string{"XX"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return operator{key: key, certificate: certificate}
}

// signed returns the list with an enveloped signature by signer over the
// reference URI; KeyInfo shows the certificates of the operators in shown,
// or the signer's alone.
func signed(t *testing.T, signer operator, uri string, shown ...operator) *etree.Document {
	t.Helper()
	if len(shown) == 0 {
		shown = []operator{signer}
	}
	var keyInfo strings.Builder
	for _, certificate := range shown {
		keyInfo.WriteString(`<ds:X509Certificate>` + base64.StdEncoding.EncodeToString(certificate.certificate.Raw) + `</ds:X509Certificate>`)
	}
	document := etree.NewDocument()
	if err := document.ReadFromString(list); err != nil {
		t.Fatal(err)
	}
	signature := etree.NewDocument()
	if err := signature.ReadFromString(`<ds:Signature xmlns:ds="` + xmldsig.Namespace + `"><ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + xmldsig.ExcC14N + `"/>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
		`<ds:Reference URI="` + uri + `"><ds:Transforms><ds:Transform Algorithm="` + xmldsig.EnvelopedSignature + `"/>` +
		`<ds:Transform Algorithm="` + xmldsig.ExcC14N + `"/></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>` +
		`</ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data>` + keyInfo.String() +
		`</ds:X509Data></ds:KeyInfo></ds:Signature>`); err != nil {
		t.Fatal(err)
	}
	document.Root().AddChild(signature.Root())

	element := document.Root().SelectElement("Signature")
	reference := element.FindElement("./SignedInfo/Reference")
	data, err := xmldsig.ReferenceData(document, element, reference, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	reference.SelectElement("DigestValue").SetText(base64.StdEncoding.EncodeToString(digest[:]))
	canonical, err := xmldsig.Canonicalize(element.SelectElement("SignedInfo"), xmldsig.ExcC14N, "")
	if err != nil {
		t.Fatal(err)
	}
	hashed := sha256.Sum256(canonical)
	value, err := rsa.SignPKCS1v15(rand.Reader, signer.key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatal(err)
	}
	element.SelectElement("SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))
	return document
}

func bytesOf(t *testing.T, document *etree.Document) []byte {
	t.Helper()
	content, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestAListSignedWholeByThePublishedOperatorIsTrusted(t *testing.T) {
	published := newOperator(t, "Scheme Operator")
	for _, uri := range []string{"", "#TSL-1"} {
		integrity := trustinfra.InspectListSignatureWithAnchors(bytesOf(t, signed(t, published, uri)), []*x509.Certificate{published.certificate})
		if !integrity.Signed || !integrity.SignatureValid || !integrity.Trusted || !strings.Contains(integrity.Signer, "Scheme Operator") {
			t.Errorf("URI %q: %+v", uri, integrity)
		}
	}
}

func TestTheOperatorIsFoundAmongTheCertificatesShown(t *testing.T) {
	published, other := newOperator(t, "Scheme Operator"), newOperator(t, "Some CA")
	integrity := trustinfra.InspectListSignatureWithAnchors(bytesOf(t, signed(t, published, "", other, published)), []*x509.Certificate{published.certificate})
	if !integrity.Trusted || !strings.Contains(integrity.Signer, "Scheme Operator") {
		t.Errorf("%+v", integrity)
	}
}

func TestAListIsNotTrustedWhen(t *testing.T) {
	published, impostor := newOperator(t, "Scheme Operator"), newOperator(t, "Impostor")
	anchors := []*x509.Certificate{published.certificate}

	added := signed(t, published, "")
	added.Root().SelectElement("TrustServiceProviderList").AddChild(
		added.Root().FindElement("./TrustServiceProviderList/TrustServiceProvider").Copy())

	nested := signed(t, published, "")
	nested.Root().SelectElement("SchemeInformation").AddChild(nested.Root().SelectElement("Signature"))

	for name, check := range map[string]struct {
		content []byte
		reason  string
	}{
		"an authority is added after signing": {bytesOf(t, added), "does not verify"},
		"the signature covers one part only":  {bytesOf(t, signed(t, published, "#scheme")), "does not cover the whole list"},
		"another key signs it":                {bytesOf(t, signed(t, impostor, "")), "not the one published"},
		"its signature is not the list's own": {bytesOf(t, nested), "carries no XML signature"},
	} {
		integrity := trustinfra.InspectListSignatureWithAnchors(check.content, anchors)
		if integrity.Trusted || !strings.Contains(integrity.Reason, check.reason) {
			t.Errorf("%s: %+v", name, integrity)
		}
	}
	if integrity := trustinfra.InspectListSignatureWithAnchors(bytesOf(t, signed(t, published, "")), nil); integrity.Trusted {
		t.Errorf("no operator is published: %+v", integrity)
	}
}
