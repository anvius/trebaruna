//go:build cgo

package infrastructure_test

// Signing with a Brainpool key on a card, as German health professionals'
// cards (HBA) sign: SoftHSM generates the key inside the token on each
// curve, openssl issues its certificate from a Brainpool authority the
// token also holds, and trebaruna signs CAdES, XAdES and PAdES with it.
// openssl checks the CMS envelope; lxml and Python's cryptography (libxml2
// and OpenSSL, nothing of trebaruna's) check the XML signature value, as
// this system's xmlsec1 cannot load such a key; EU DSS, when DSS_LIB names
// its jars, judges the CAdES, XAdES and PAdES signatures; trebaruna's
// verifier, which reads Brainpool since 0.97.0, checks each one whole.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verification "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
	"codeberg.org/simplicer/trebaruna/tests/support/dss"
)

// brainpoolCard is a token holding a Brainpool key it generated, its
// certificate and the authority that issued it.
type brainpoolCard struct {
	token     softHSM
	authority string // the authority's PEM file
	holder    string // the signer's certificate PEM file
}

func newBrainpoolCard(t *testing.T, curve string) brainpoolCard {
	t.Helper()
	for _, tool := range []string{"openssl", "pkcs11-tool"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
	token := startSoftHSM(t)
	pkcs11 := func(arguments ...string) {
		t.Helper()
		command := exec.Command("pkcs11-tool", append([]string{"--module", token.module, "--slot", token.slot, "--login", "--pin", token.pin}, arguments...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("pkcs11-tool %v: %v\n%s", arguments, err, output)
		}
	}
	openssl := func(arguments ...string) {
		t.Helper()
		command := exec.Command("openssl", arguments...)
		command.Dir = token.directory
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", arguments, err, output)
		}
	}
	pkcs11("--keypairgen", "--key-type", "EC:"+curve, "--id", "01", "--label", "signing-key")
	pkcs11("--id", "01", "--read-object", "--type", "pubkey", "--output-file", filepath.Join(token.directory, "public.der"))
	openssl("pkey", "-pubin", "-inform", "DER", "-in", "public.der", "-out", "public.pem")
	openssl("ecparam", "-name", curve, "-genkey", "-noout", "-out", "ca.key")
	openssl("req", "-x509", "-new", "-key", "ca.key", "-subj", "/C=DE/O=Aerztekammer/CN=HBA-CA 7", "-days", "30",
		"-addext", "basicConstraints=critical,CA:true", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "ca.pem")
	os.WriteFile(filepath.Join(token.directory, "signer.cnf"), []byte("keyUsage=critical,nonRepudiation\n"), 0o600)
	openssl("x509", "-new", "-force_pubkey", "public.pem", "-subj", "/C=DE/serialNumber=IDCDE-80276883110000017222/CN=Dr. Anna Mueller",
		"-CA", "ca.pem", "-CAkey", "ca.key", "-days", "30", "-extfile", "signer.cnf", "-out", "signer.pem")
	card := brainpoolCard{token: token, authority: filepath.Join(token.directory, "ca.pem"), holder: filepath.Join(token.directory, "signer.pem")}
	importCertificate(t, token, "01", "signing-key", readFileOrFail(t, card.holder))
	importCertificate(t, token, "02", "authority", readFileOrFail(t, card.authority))
	return card
}

func (c brainpoolCard) signer(t *testing.T) domain.Signer {
	t.Helper()
	signer, err := domain.NewSigner("Token", domain.FromToken, domain.WithToken(c.token.module, c.token.label, c.token.pin))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func (c brainpoolCard) anchor(t *testing.T) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(readFileOrFail(t, c.authority))
	authority, err := brainpool.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

// xmlSignatureJudge checks an XML signature's value with lxml and
// cryptography: SignedInfo canonicalised as it declares, the r and s of
// SignatureValue checked against the certificate's key.
const xmlSignatureJudge = `
import sys, base64
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
DS = "http://www.w3.org/2000/09/xmldsig#"
document = etree.parse(sys.argv[1])
signature = document.find(".//{%s}Signature" % DS)
info = signature.find("{%s}SignedInfo" % DS)
method = info.find("{%s}CanonicalizationMethod" % DS).get("Algorithm")
exclusive = "exc-c14n" in method
canonical = etree.tostring(info, method="c14n", exclusive=exclusive, with_comments=method.endswith("#WithComments"))
value = base64.b64decode("".join(signature.find("{%s}SignatureValue" % DS).text.split()))
half = len(value) // 2
certificate = x509.load_pem_x509_certificate(open(sys.argv[2], "rb").read())
key = certificate.public_key()
key.verify(encode_dss_signature(int.from_bytes(value[:half], "big"), int.from_bytes(value[half:], "big")), canonical, ec.ECDSA(hashes.SHA256()))
print(key.curve.name, half)
`

func judgeXMLSignature(t *testing.T, signed []byte, certificate string) string {
	t.Helper()
	if exec.Command("python3", "-I", "-c", "import lxml, cryptography").Run() != nil {
		t.Skip("python3 with lxml and cryptography is not available")
	}
	path := filepath.Join(t.TempDir(), "signed.xml")
	os.WriteFile(path, signed, 0o600)
	output, err := exec.Command("python3", "-I", "-c", xmlSignatureJudge, path, certificate).CombinedOutput()
	if err != nil {
		t.Errorf("the XML signature value does not verify: %v\n%s", err, output)
	}
	return string(output)
}

// wordDocument is a minimal Word document.
func wordDocument(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for name, content := range map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
			`<w:body><w:p><w:r><w:t>Rezept: Ibuprofen 400</w:t></w:r></w:p></w:body></w:document>`,
	} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write([]byte(content))
	}
	writer.Close()
	return output.Bytes()
}

// textDocument is a minimal OpenDocument text, its mimetype first and
// stored.
func textDocument(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range []struct {
		name, content string
		method        uint16
	}{
		{"mimetype", "application/vnd.oasis.opendocument.text", zip.Store},
		{"content.xml", `<?xml version="1.0" encoding="UTF-8"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.3"><office:body>Rezept</office:body></office:document-content>`, zip.Deflate},
		{"META-INF/manifest.xml", `<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">` +
			`<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>` +
			`<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/></manifest:manifest>`, zip.Deflate},
	} {
		file, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: entry.method})
		if err != nil {
			t.Fatal(err)
		}
		file.Write([]byte(entry.content))
	}
	writer.Close()
	return output.Bytes()
}

// onePagePDF is a minimal one-page PDF.
func onePagePDF() []byte {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> >>",
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for index, body := range objects {
		offsets[index] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", index+1, body)
	}
	start := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /ID [<0102030405060708090A0B0C0D0E0F10> <0102030405060708090A0B0C0D0E0F10>] >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, start)
	return out.Bytes()
}

func TestACardWithABrainpoolKeySigns(t *testing.T) {
	for curve, width := range map[string]string{"brainpoolP256r1": "32", "brainpoolP384r1": "48", "brainpoolP512r1": "64"} {
		t.Run(curve, func(t *testing.T) {
			card := newBrainpoolCard(t, curve)
			signer := card.signer(t)

			keyPair, err := infrastructure.LoadKeyPair(signer)
			if err != nil {
				t.Fatalf("the card's key pair: %v", err)
			}
			if _, ok := keyPair.Certificate.PublicKey.(*brainpool.PublicKey); !ok || keyPair.Certificate.Subject.CommonName != "Dr. Anna Mueller" ||
				len(keyPair.Chain) != 1 || keyPair.Chain[0].Subject.CommonName != "HBA-CA 7" || keyPair.SelfSigned {
				t.Errorf("key %T, holder %q, chain %d, self-signed %v", keyPair.Certificate.PublicKey, keyPair.Certificate.Subject.CommonName,
					len(keyPair.Chain), keyPair.SelfSigned)
			}
			keyPair.Close()

			// The card's listing shows the certificate, as `trebaruna token` does.
			slots, err := infrastructure.TokenInspector{Module: card.token.module}.Inspect()
			listed := false
			for _, slot := range slots {
				for _, certificate := range slot.Certificates {
					listed = listed || slot.TokenLabel == card.token.label && strings.Contains(certificate.Subject, "Dr. Anna Mueller")
				}
			}
			if err != nil || !listed {
				t.Errorf("the card's listing: %v %+v", err, slots)
			}

			// CAdES: openssl checks the envelope against the authority.
			envelope, err := infrastructure.NewCadesSigner(nil).SignCades(context.Background(), application.CadesRequest{
				Content: []byte("Rezept: Ibuprofen 400\n"), Signer: signer, Level: domain.BES})
			if err != nil {
				t.Fatalf("CAdES: %v", err)
			}
			if err := verifyWithOpenSSL(t, envelope, readFileOrFail(t, card.authority)); err != nil {
				t.Errorf("openssl refuses the CAdES envelope: %v", err)
			}
			if dss.Available() {
				dss.Judged(t, dss.Judge(t, "rezept.txt.p7m", envelope, nil, card.anchor(t)), 1, "CAdES-BASELINE-B", true)
			}
			cadesPath := filepath.Join(t.TempDir(), "rezept.txt.p7m")
			os.WriteFile(cadesPath, envelope, 0o600)
			cades := verification.NewCadesVerifier().WithAnchorCertificates(x509.NewCertPool(), nil, []*x509.Certificate{card.anchor(t)})
			if reports, err := cades.Extract(cadesPath); err != nil || len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood ||
				reports[0].CertificateStatus != verificationdomain.StatusGood {
				t.Errorf("trebaruna's CAdES verdict: %v %+v", err, reports)
			}

			// XAdES: the value is r and s as wide as the curve's order.
			document := []byte(`<?xml version="1.0" encoding="UTF-8"?><Rezept><Arznei>Ibuprofen 400</Arznei></Rezept>`)
			signedXML, err := infrastructure.NewXadesSigner(nil).SignXades(context.Background(), application.XadesRequest{
				Content: document, Signer: signer, Level: domain.BES})
			if err != nil {
				t.Fatalf("XAdES: %v", err)
			}
			if got := judgeXMLSignature(t, signedXML, card.holder); got != "" && got != curve+" "+width+"\n" {
				t.Errorf("the judge read %q", got)
			}
			if dss.Available() {
				dss.Judged(t, dss.Judge(t, "rezept.xml", signedXML, nil, card.anchor(t)), 1, "XAdES-BASELINE-B", true)
			}
			xadesPath := filepath.Join(t.TempDir(), "rezept.xml")
			os.WriteFile(xadesPath, signedXML, 0o600)
			if reports, err := verification.NewXadesVerifier().Extract(xadesPath); err != nil || len(reports) != 1 ||
				reports[0].Integrity != verificationdomain.StatusGood {
				t.Errorf("trebaruna's XAdES verdict: %v %+v", err, reports)
			}

			// A second signature counter-signs the first, from the same card.
			countersigned, err := infrastructure.NewXadesSigner(nil).SignXades(context.Background(), application.XadesRequest{
				Content: signedXML, Signer: signer, Level: domain.BES, Countersign: "leaves"})
			if err != nil {
				t.Fatalf("XAdES counter-signature: %v", err)
			}
			os.WriteFile(xadesPath, countersigned, 0o600)
			if reports, err := verification.NewXadesVerifier().Extract(xadesPath); err != nil || len(reports) != 2 ||
				reports[0].Integrity != verificationdomain.StatusGood || reports[1].Integrity != verificationdomain.StatusGood {
				t.Errorf("trebaruna's verdict on the counter-signed XAdES: %v %+v", err, reports)
			}

			// OOXML: the package signature, XML-DSig inside the document.
			office, err := infrastructure.NewOoxmlSigner(infrastructure.NewXadesSigner(nil)).SignOoxml(context.Background(),
				application.XadesRequest{Content: wordDocument(t), Signer: signer, Level: domain.BES})
			if err != nil {
				t.Fatalf("OOXML: %v", err)
			}
			officePath := filepath.Join(t.TempDir(), "rezept.docx")
			os.WriteFile(officePath, office, 0o600)
			if reports, err := verification.NewOoxmlVerifier(verification.NewXadesVerifier()).Extract(officePath); err != nil || len(reports) != 1 ||
				reports[0].Integrity != verificationdomain.StatusGood {
				t.Errorf("trebaruna's OOXML verdict: %v %+v", err, reports)
			}

			// OpenDocument: the document signed inside itself, as LibreOffice does.
			text, err := infrastructure.NewOdfSigner(infrastructure.NewXadesSigner(nil)).SignOdf(context.Background(),
				application.XadesRequest{Content: textDocument(t), Signer: signer, Level: domain.BES})
			if err != nil {
				t.Fatalf("OpenDocument: %v", err)
			}
			textPath := filepath.Join(t.TempDir(), "rezept.odt")
			os.WriteFile(textPath, text, 0o600)
			if reports, err := verification.NewOdfVerifier(verification.NewXadesVerifier()).Extract(textPath); err != nil || len(reports) != 1 ||
				reports[0].Integrity != verificationdomain.StatusGood {
				t.Errorf("trebaruna's OpenDocument verdict: %v %+v", err, reports)
			}

			// PAdES: trebaruna's verifier, anchored at the authority.
			signedPDF, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
				Content: onePagePDF(), Signer: signer, Level: domain.BES, Invisible: true, SignedAt: time.Now()})
			if err != nil {
				t.Fatalf("PAdES: %v", err)
			}
			if dss.Available() {
				dss.Judged(t, dss.Judge(t, "rezept.pdf", signedPDF, nil, card.anchor(t)), 1, "PAdES-BASELINE-B", true)
			}
			pdfPath := filepath.Join(t.TempDir(), "rezept.pdf")
			os.WriteFile(pdfPath, signedPDF, 0o600)
			pades := verification.NewPDFVerifier()
			pades.Anchors = []*x509.Certificate{card.anchor(t)}
			if reports, err := pades.Extract(pdfPath); err != nil || len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood ||
				reports[0].CertificateStatus != verificationdomain.StatusGood {
				t.Errorf("trebaruna's PAdES verdict: %v %+v", err, reports)
			}
		})
	}
}

// TestASelfSignedBrainpoolCardIsSaidToBe: a card whose certificate its own
// key signed, as test and some company cards are, is read as self-signed,
// and what it signs verifies against that certificate.
func TestASelfSignedBrainpoolCardIsSaidToBe(t *testing.T) {
	card := newBrainpoolCard(t, "brainpoolP256r1")
	token, directory := card.token, card.token.directory
	run := func(name string, arguments ...string) {
		t.Helper()
		command := exec.Command(name, arguments...)
		command.Dir = directory
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, arguments, err, output)
		}
	}
	// openssl writes the certificate's contents, signed by a throwaway key;
	// the card signs them, and the certificate is put back together.
	run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "throwaway.key")
	// No key identifiers: openssl would take the authority's from the
	// throwaway key, and the certificate would not name itself as issuer.
	os.WriteFile(filepath.Join(directory, "self.cnf"), []byte("subjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n"), 0o600)
	run("openssl", "x509", "-new", "-force_pubkey", "public.pem", "-subj", "/C=DE/CN=Selbst Karte", "-key", "throwaway.key", "-days", "30",
		"-extfile", "self.cnf", "-outform", "DER", "-out", "draft.der")
	draft, err := brainpool.ParseCertificate(readFileOrFail(t, filepath.Join(directory, "draft.der")))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(draft.RawTBSCertificate)
	os.WriteFile(filepath.Join(directory, "tbs.sha256"), digest[:], 0o600)
	run("pkcs11-tool", "--module", token.module, "--slot", token.slot, "--login", "--pin", token.pin, "--id", "01",
		"--sign", "-m", "ECDSA", "--signature-format", "openssl", "-i", "tbs.sha256", "-o", "tbs.sig")
	value := readFileOrFail(t, filepath.Join(directory, "tbs.sig"))
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Value     asn1.BitString
	}{asn1.RawValue{FullBytes: draft.RawTBSCertificate}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		asn1.BitString{Bytes: value, BitLength: 8 * len(value)}})
	if err != nil {
		t.Fatal(err)
	}
	self := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	run("pkcs11-tool", "--module", token.module, "--slot", token.slot, "--login", "--pin", token.pin, "--delete-object", "--type", "cert", "--id", "01")
	importCertificate(t, token, "01", "signing-key", self)

	keyPair, err := infrastructure.LoadKeyPair(card.signer(t))
	if err != nil {
		t.Fatal(err)
	}
	if !keyPair.SelfSigned || keyPair.Certificate.Subject.CommonName != "Selbst Karte" {
		t.Errorf("self-signed %v, holder %q", keyPair.SelfSigned, keyPair.Certificate.Subject.CommonName)
	}
	keyPair.Close()
	envelope, err := infrastructure.NewCadesSigner(nil).SignCades(context.Background(), application.CadesRequest{
		Content: []byte("Selbst signiert\n"), Signer: card.signer(t), Level: domain.BES})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWithOpenSSL(t, envelope, self); err != nil {
		t.Errorf("openssl refuses the envelope of a self-signed card: %v", err)
	}
}

// TestACounterSignatureThatWouldBreakABrainpoolSignatureIsNotWritten: a
// second signature, made by the card, whose enveloped transform removes
// only itself covers the first; counter-signing the first would break it,
// and nothing is written.
func TestACounterSignatureThatWouldBreakABrainpoolSignatureIsNotWritten(t *testing.T) {
	card := newBrainpoolCard(t, "brainpoolP256r1")
	signer := card.signer(t)
	signed, err := infrastructure.NewXadesSigner(nil).SignXades(context.Background(), application.XadesRequest{
		Content: []byte(`<Rezept><Arznei>Ibuprofen 400</Arznei></Rezept>`), Signer: signer, Level: domain.BES})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(readFileOrFail(t, card.holder))
	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	outer := etree.NewDocument()
	outer.ReadFromString(`<ds:Signature xmlns:ds="` + xmldsig.Namespace + `" Id="outer"><ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + xmldsig.C14N10 + `"/>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>` +
		`<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="` + xmldsig.EnvelopedSignature + `"/></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>` +
		`</ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(block.Bytes) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`)
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
	keyPair, err := infrastructure.LoadKeyPair(signer)
	if err != nil {
		t.Fatal(err)
	}
	der, err := keyPair.Signer.Sign(rand.Reader, hashed[:], crypto.SHA256)
	keyPair.Close()
	if err != nil {
		t.Fatal(err)
	}
	var parts struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parts); err != nil {
		t.Fatal(err)
	}
	value := make([]byte, 64)
	parts.R.FillBytes(value[:32])
	parts.S.FillBytes(value[32:])
	element.SelectElement("SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))
	twoSigned, _ := document.WriteToBytes()
	path := filepath.Join(t.TempDir(), "two.xml")
	os.WriteFile(path, twoSigned, 0o600)
	if reports, err := verification.NewXadesVerifier().Extract(path); err != nil || len(reports) != 2 ||
		reports[0].Integrity != verificationdomain.StatusGood || reports[1].Integrity != verificationdomain.StatusGood {
		t.Fatalf("the two signatures: %v %+v", err, reports)
	}

	_, err = infrastructure.NewXadesSigner(nil).SignXades(context.Background(), application.XadesRequest{
		Content: twoSigned, Signer: signer, Level: domain.BES, Countersign: "leaves"})
	if err == nil || !strings.Contains(err.Error(), "would break") {
		t.Errorf("counter-signing under a Brainpool signature that covers it: %v", err)
	}
}
