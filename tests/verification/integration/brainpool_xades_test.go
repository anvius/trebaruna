package integration_test

// XML signatures made with brainpool keys. This system's xmlsec1 cannot
// load such a key, so the signature is assembled here: the document and
// SignedInfo canonicalised by trebaruna's canonicaliser (judged against
// xmlsec1 on other curves), the SignedInfo signed by openssl with the
// brainpool key, the value written as XML-Signature's r and s.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

const inclusiveC14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"

// brainpoolXML signs a prescription, enveloped, with a brainpool key.
func brainpoolXML(t *testing.T, curve string) (string, *x509.Certificate) {
	t.Helper()
	directory := t.TempDir()
	run := func(arguments ...string) { brainpoolOpenSSL(t, directory, arguments...) }
	run("ecparam", "-name", curve, "-genkey", "-noout", "-out", "ca.key")
	run("req", "-utf8", "-x509", "-new", "-key", "ca.key", "-subj", "/C=DE/O=Ärztekammer/CN=HBA-CA 7", "-days", "30",
		"-addext", "basicConstraints=critical,CA:true", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-outform", "DER", "-out", "ca.der")
	run("ecparam", "-name", curve, "-genkey", "-noout", "-out", "signer.key")
	run("req", "-utf8", "-new", "-key", "signer.key", "-subj", "/C=DE/CN=Dr. Anna Müller", "-out", "signer.csr")
	os.WriteFile(filepath.Join(directory, "ext.cnf"), []byte("keyUsage=critical,nonRepudiation\n"), 0o600)
	run("x509", "-req", "-in", "signer.csr", "-CA", "ca.der", "-CAform", "DER", "-CAkey", "ca.key", "-days", "30", "-extfile", "ext.cnf",
		"-outform", "DER", "-out", "signer.der")
	authorityDER, _ := os.ReadFile(filepath.Join(directory, "ca.der"))
	signerDER, _ := os.ReadFile(filepath.Join(directory, "signer.der"))

	unsigned := `<Rezept xmlns="urn:example:rezept"><Medikament>Ibuprofen 400</Medikament></Rezept>`
	digest := sha256.Sum256([]byte(unsigned))
	signature := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + inclusiveC14N + `"/>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>` +
		`<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
		`<ds:Transform Algorithm="` + inclusiveC14N + `"/></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</ds:DigestValue></ds:Reference></ds:SignedInfo>` +
		`<ds:SignatureValue>VALUE</ds:SignatureValue><ds:KeyInfo><ds:X509Data>` +
		`<ds:X509Certificate>` + base64.StdEncoding.EncodeToString(signerDER) + `</ds:X509Certificate>` +
		`<ds:X509Certificate>` + base64.StdEncoding.EncodeToString(authorityDER) + `</ds:X509Certificate>` +
		`</ds:X509Data></ds:KeyInfo></ds:Signature>`
	document := strings.Replace(unsigned, "</Rezept>", signature+"</Rezept>", 1)

	tree := etree.NewDocument()
	if err := tree.ReadFromString(document); err != nil {
		t.Fatal(err)
	}
	canonical, err := xmldsig.Canonicalize(tree.FindElement("//SignedInfo"), inclusiveC14N, "")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(directory, "signedinfo"), canonical, 0o600)
	command := exec.Command("openssl", "dgst", "-sha256", "-sign", "signer.key", "signedinfo")
	command.Dir = directory
	der, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var values struct{ R, S *big.Int }
	asn1.Unmarshal(der, &values)
	key, _ := brainpool.ParsePublicKey(mustSPKI(t, signerDER))
	size := (key.Curve.N.BitLen() + 7) / 8
	raw := append(values.R.FillBytes(make([]byte, size)), values.S.FillBytes(make([]byte, size))...)
	document = strings.Replace(document, "VALUE", base64.StdEncoding.EncodeToString(raw), 1)

	path := filepath.Join(directory, "rezept.xml")
	os.WriteFile(path, []byte(document), 0o600)
	authority, _ := brainpool.ParseCertificate(authorityDER)
	return path, authority
}

func mustSPKI(t *testing.T, der []byte) []byte {
	t.Helper()
	certificate, err := brainpool.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate.RawSubjectPublicKeyInfo
}

func TestABrainpoolXMLSignatureIsReadAndChecked(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	for _, curve := range []string{"brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"} {
		path, authority := brainpoolXML(t, curve)
		reports, err := infrastructure.NewXadesVerifier().Extract(path)
		if err != nil || len(reports) != 1 {
			t.Fatalf("%s: %v %+v", curve, err, reports)
		}
		if reports[0].Integrity != domain.StatusGood || reports[0].SignerName != "Dr. Anna Müller" {
			t.Errorf("%s: integrity %s, signer %q, findings %+v", curve, reports[0].Integrity, reports[0].SignerName, reports[0].Findings)
		}
		anchored := infrastructure.NewXadesVerifier().WithAnchorCertificates(x509.NewCertPool(), nil, []*x509.Certificate{authority})
		if reports, err := anchored.Extract(path); err != nil || reports[0].CertificateStatus != domain.StatusGood {
			t.Errorf("%s: the chain to the anchored authority: %v %s", curve, err, reports[0].CertificateStatus)
		}
		_, impostor := brainpoolXML(t, curve)
		misanchored := infrastructure.NewXadesVerifier().WithAnchorCertificates(x509.NewCertPool(), nil, []*x509.Certificate{impostor})
		if reports, err := misanchored.Extract(path); err != nil || reports[0].CertificateStatus == domain.StatusGood {
			t.Errorf("%s: an impostor authority anchored the chain: %v", curve, err)
		}
		content, _ := os.ReadFile(path)
		tampered := filepath.Join(t.TempDir(), "tampered.xml")
		os.WriteFile(tampered, []byte(strings.Replace(string(content), "Ibuprofen 400", "Ibuprofen 800", 1)), 0o600)
		if reports, err := infrastructure.NewXadesVerifier().Extract(tampered); err != nil || reports[0].Integrity != domain.StatusBad {
			t.Errorf("%s: a changed prescription: %v %+v", curve, err, reports)
		}
	}
}
