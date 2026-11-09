package integration_test

// Documents named by address and signed by a digest given (AutoFirma's
// XAdES Externally Detached, with or without useManifest): the references
// carry the digests, the content never reaches trebaruna, and a verifier
// that has the documents checks them.

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

var (
	firstDocument  = []byte("%PDF-1.7 modelo 303\n")
	secondDocument = []byte("<anexo>II</anexo>")
)

func referencedDocuments(t *testing.T) []application.ReferencedDocument {
	t.Helper()
	first, second := sha256.Sum256(firstDocument), sha512.Sum512(secondDocument)
	firstDigest, err := domain.NewContentDigest("SHA-256", first[:])
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := domain.NewContentDigest("SHA-512", second[:])
	if err != nil {
		t.Fatal(err)
	}
	return []application.ReferencedDocument{
		{URI: "https://sede.example/expediente/modelo303.pdf", Digest: firstDigest, MimeType: "application/pdf"},
		{URI: "https://sede.example/expediente/anexo.xml?v=2&k=1", Digest: secondDigest},
	}
}

func signReferenced(t *testing.T, manifest bool, level domain.Level) ([]byte, error) {
	t.Helper()
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	return infrastructure.NewXadesSigner(nil).SignXades(t.Context(), application.XadesRequest{Signer: signer, Level: level,
		Packaging: domain.XMLDetached, Referenced: referencedDocuments(t), Manifest: manifest})
}

// checkSigned verifies the one signature with the documents the resolver
// hands over.
func checkSigned(t *testing.T, signed []byte, resolve xmldsig.Resolver) error {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	signature := document.FindElement("//Signature")
	certificate := parseEmbeddedCertificate(t, signature)
	return xmldsig.Check(document, signature, certificate.PublicKey, resolve)
}

func TestDocumentsNamedByAddressAreSignedByTheirDigests(t *testing.T) {
	signed, err := signReferenced(t, false, domain.BES)
	if err != nil {
		t.Fatal(err)
	}
	documents := map[string][]byte{
		"https://sede.example/expediente/modelo303.pdf":     firstDocument,
		"https://sede.example/expediente/anexo.xml?v=2&k=1": secondDocument,
	}
	resolve := func(uri string) ([]byte, error) {
		if content, ok := documents[uri]; ok {
			return content, nil
		}
		return nil, xmldsig.ErrContentMissing
	}
	if err := checkSigned(t, signed, resolve); err != nil {
		t.Errorf("with the documents, the signature verifies: %v", err)
	}
	documents["https://sede.example/expediente/anexo.xml?v=2&k=1"] = []byte("<anexo>III</anexo>")
	if err := checkSigned(t, signed, resolve); !errors.Is(err, xmldsig.ErrModified) {
		t.Errorf("another document under the same address is caught: %v", err)
	}
	text := string(signed)
	for _, wanted := range []string{`URI="https://sede.example/expediente/anexo.xml?v=2&amp;k=1"`, "xmlenc#sha512",
		"<xades:MimeType>application/pdf</xades:MimeType>", "<xades:MimeType>application/octet-stream</xades:MimeType>"} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the signature lacks %s", wanted)
		}
	}
	writeForJudges(t, "referenced.xml", signed)
}

func TestAManifestHoldsTheReferencesToDocumentsNamedByAddress(t *testing.T) {
	signed, err := signReferenced(t, true, domain.BES)
	if err != nil {
		t.Fatal(err)
	}
	// The signature verifies without the documents: SignedInfo covers the
	// manifest, and the manifest the digests.
	if err := checkSigned(t, signed, nil); err != nil {
		t.Errorf("the manifest signature verifies: %v", err)
	}
	document := etree.NewDocument()
	_ = document.ReadFromBytes(signed)
	signedInfo := document.FindElement("//SignedInfo")
	references := signedInfo.SelectElements("Reference")
	if len(references) != 2 || references[0].SelectAttrValue("Type", "") != "http://www.w3.org/2000/09/xmldsig#Manifest" {
		t.Fatalf("SignedInfo references the manifest and the signed properties: %d references", len(references))
	}
	manifest := document.FindElement("//Object/Manifest")
	if manifest == nil || "#"+manifest.SelectAttrValue("Id", "") != references[0].SelectAttrValue("URI", "") ||
		len(manifest.SelectElements("Reference")) != 2 {
		t.Fatal("the manifest, in an Object, holds both references")
	}
	for index, reference := range manifest.SelectElements("Reference") {
		given := referencedDocuments(t)[index]
		if reference.SelectAttrValue("URI", "") != given.URI ||
			reference.FindElement("DigestValue").Text() != base64.StdEncoding.EncodeToString(given.Digest.Value()) {
			t.Errorf("manifest reference %d does not carry the address and digest given", index)
		}
	}
	writeForJudges(t, "manifest.xml", signed)
}

func TestDocumentsNamedByAddressAreSignedAlone(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	referenced := referencedDocuments(t)
	for name, test := range map[string]struct {
		request application.XadesRequest
		reason  string
	}{
		"with content": {application.XadesRequest{Signer: signer, Level: domain.BES, Packaging: domain.XMLDetached, Referenced: referenced,
			Content: []byte("x"), DocumentName: "x"}, "signed alone"},
		"enveloping": {application.XadesRequest{Signer: signer, Level: domain.BES, Packaging: domain.XMLEnveloping, Referenced: referenced},
			"signed alone"},
		"empty manifest": {application.XadesRequest{Signer: signer, Level: domain.BES, Packaging: domain.XMLDetached, Manifest: true},
			"a manifest references documents"},
		"archival": {application.XadesRequest{Signer: signer, Level: domain.LTA, Packaging: domain.XMLDetached, Referenced: referenced,
			TimestampURL: "http://tsa.invalid"}, "only their digests are here"},
		"no address": {application.XadesRequest{Signer: signer, Level: domain.BES, Packaging: domain.XMLDetached,
			Referenced: []application.ReferencedDocument{{Digest: referenced[0].Digest}}}, "needs its address"},
	} {
		if _, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), test.request); err == nil || !strings.Contains(err.Error(), test.reason) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// writeForJudges keeps a signature for xmlsec1 when TREBARUNA_JUDGES names
// a directory.
func writeForJudges(t *testing.T, name string, content []byte) {
	t.Helper()
	if directory := os.Getenv("TREBARUNA_JUDGES"); directory != "" {
		_ = os.WriteFile(filepath.Join(directory, name), content, 0o600)
	}
}

// parseEmbeddedCertificate reads the signer's certificate from KeyInfo.
func parseEmbeddedCertificate(t *testing.T, signature *etree.Element) *x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(signature.FindElement(".//X509Certificate").Text())
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
