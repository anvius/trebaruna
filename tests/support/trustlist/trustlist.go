// Package trustlist signs trust lists for tests: a key and certificate per
// operator, and an enveloped signature over the whole list, as a scheme
// operator or the Commission signs one.
package trustlist

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// Operator is a key and its certificate.
type Operator struct {
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
}

// NewOperator makes a throwaway operator.
func NewOperator(t *testing.T, name string) Operator {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Operator{Key: key, Certificate: certificate}
}

// Base64 is the certificate as a list writes it.
func (o Operator) Base64() string { return base64.StdEncoding.EncodeToString(o.Certificate.Raw) }

// Sign returns the list with an enveloped signature by signer over all of
// it (Reference URI=""), its certificate in KeyInfo.
func Sign(t *testing.T, list string, signer Operator) []byte {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromString(list); err != nil {
		t.Fatal(err)
	}
	signature := etree.NewDocument()
	if err := signature.ReadFromString(`<ds:Signature xmlns:ds="` + xmldsig.Namespace + `"><ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + xmldsig.ExcC14N + `"/>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
		`<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="` + xmldsig.EnvelopedSignature + `"/>` +
		`<ds:Transform Algorithm="` + xmldsig.ExcC14N + `"/></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>` +
		`</ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + signer.Base64() +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`); err != nil {
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
	value, err := rsa.SignPKCS1v15(rand.Reader, signer.Key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatal(err)
	}
	element.SelectElement("SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))
	content, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return content
}
