package infrastructure_test

// Pages ask for signature policies as AutoFirma 1.9 reads them
// (docs/afirma-protocol.md, F): the expPolicy shorthand, the policy's parts,
// or a FacturaE invoice, which always carries FacturaE's policy.

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
)

const (
	invoice     = `<fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml"><FileHeader/></fe:Facturae>`
	ageOID      = "urn:oid:2.16.724.1.3.1.1.2.1.9"
	ageDocument = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf"
	facturaE31  = "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf"
)

func signPage(t *testing.T, formatName string, properties map[string]string, data []byte) (application.Signed, error) {
	t.Helper()
	maria, _ := identity(t, "MARIA GARCIA", 21)
	return infrastructure.NewNativePageSigner().Sign(context.Background(), application.PageSignature{Crypto: domain.Sign,
		Format: format(t, formatName), Algorithm: "SHA256", Properties: properties, Data: data, Key: maria})
}

func wantFailure(t *testing.T, err error, code domain.FailureCode, what string) {
	t.Helper()
	var failure domain.Failure
	if !errors.As(err, &failure) || failure.Code != code {
		t.Errorf("%s: %v, want SAF_%02d", what, err, code)
	}
}

// TestFirmaAGEForACAdESPage: the AGE 1.9 policy, the data inside below 1 MiB
// and beside it from there, and openssl verifies both.
func TestFirmaAGEForACAdESPage(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	small := []byte("solicitud\n")
	signed, err := signPage(t, "CAdES", map[string]string{"expPolicy": "FirmaAGE"}, small)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed.Signature, []byte(ageDocument)) {
		t.Error("the signature does not declare the AGE policy")
	}
	opensslVerify(t, "-in", write(t, directory, "small.p7m", signed.Signature))

	large := bytes.Repeat([]byte("x"), 1<<20)
	signed, err = signPage(t, "CAdES", map[string]string{"expPolicy": "FirmaAGE"}, large)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed.Signature) > 1<<19 {
		t.Error("1 MiB of data travels beside an AGE signature, not inside")
	}
	opensslVerify(t, "-in", write(t, directory, "large.p7s", signed.Signature),
		"-content", write(t, directory, "large", large), "-binary")

	// The page's own mode wins.
	signed, err = signPage(t, "CAdES", map[string]string{"expPolicy": "FirmaAGE", "mode": "explicit"}, small)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(signed.Signature, small) {
		t.Error("mode=explicit leaves the data out")
	}
}

// TestFirmaAGEForAXAdESPage is detached unless the page asked for enveloped:
// AutoFirma's "XAdES Detached", the data in AFIRMA/CONTENT beside the
// signature.
func TestFirmaAGEForAXAdESPage(t *testing.T) {
	signed, err := signPage(t, "XAdES", map[string]string{"expPolicy": "FirmaAGE", "format": "XAdES Enveloped"}, []byte("<solicitud/>"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed.Signature, []byte(`Qualifier="OIDAsURN">`+ageOID+`<`)) {
		t.Error("an enveloped AGE signature names the policy by its OID")
	}

	for _, format := range []string{"XAdES", "XAdES Enveloping"} {
		signed, err := signPage(t, format, map[string]string{"expPolicy": "FirmaAGE"}, []byte("<solicitud/>"))
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		output := string(signed.Signature)
		if !strings.Contains(output, "<AFIRMA Id=\"AFIRMA-Root-") || !strings.Contains(output, `<CONTENT Id="CONTENT-`) {
			t.Errorf("%s with FirmaAGE is AutoFirma's XAdES Detached:\n%.300s", format, output)
		}
		if !strings.Contains(output, ageOID) {
			t.Errorf("%s: the AGE policy is missing", format)
		}
	}
}

// TestFirmaAGEForAPDFPage: the policy goes in the PDF signature's signed
// attributes (2.16.724.1.3.1.1.2.1.9, its DER in the hexadecimal
// /Contents).
func TestFirmaAGEForAPDFPage(t *testing.T) {
	signed, err := signPage(t, "PAdES", map[string]string{"expPolicy": "FirmaAGE"}, onePagePDF())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(signed.Signature, []byte("%PDF")) || !bytes.Contains(signed.Signature, []byte("060A60855401030101020109")) {
		t.Error("a PAdES AGE signature declares the policy")
	}
}

// TestPolicyRequestsTrebarunaRefuses, with AutoFirma's codes.
func TestPolicyRequestsTrebarunaRefuses(t *testing.T) {
	cases := []struct {
		what       string
		format     string
		properties map[string]string
		data       []byte
		want       domain.FailureCode
	}{
		{"FirmaAGE19, listed and refused by AutoFirma", "CAdES", map[string]string{"expPolicy": "FirmaAGE19"}, []byte("x"), domain.InvalidPolicy},
		{"FirmaAGE18 on a PDF", "PAdES", map[string]string{"expPolicy": "FirmaAGE18"}, onePagePDF(), domain.InvalidPolicy},
		{"FirmaAGE on an invoice", "FacturaE", map[string]string{"expPolicy": "FirmaAGE"}, []byte(invoice), domain.InvalidPolicy},
		{"a policy without its digest, which AutoFirma downloads", "CAdES",
			map[string]string{"policyIdentifier": "1.2.3.4"}, []byte("x"), domain.InvalidPolicy},
		{"a digest of 0", "CAdES", map[string]string{"policyIdentifier": "1.2.3.4", "policyIdentifierHash": "0"}, []byte("x"), domain.InvalidPolicy},
		{"a digest without its algorithm", "CAdES",
			map[string]string{"policyIdentifier": "1.2.3.4", "policyIdentifierHash": "G7roucf600+f03r/o0bAOQ6WAs0="}, []byte("x"), domain.InvalidPolicy},
		{"a policy named by URL in CAdES", "CAdES", map[string]string{"policyIdentifier": facturaE31,
			"policyIdentifierHash": "Ohixl6upD6av8N7pEvDABhEL6hM=", "policyIdentifierHashAlgorithm": "SHA1"}, []byte("x"), domain.InvalidPolicy},
		{"AGE's policy on an invoice", "FacturaE", map[string]string{"policyIdentifier": ageOID,
			"policyIdentifierHash": "G7roucf600+f03r/o0bAOQ6WAs0=", "policyIdentifierHashAlgorithm": "SHA1"}, []byte(invoice), domain.InvalidPolicy},
		{"a role FacturaE does not name", "FacturaE", map[string]string{"signerClaimedRoles": "notario"}, []byte(invoice), domain.InvalidPolicy},
		{"an XML that is not an invoice", "FacturaE", map[string]string{}, []byte("<pedido/>"), domain.InvalidFacturaE},
		{"auto on a signed invoice, never a plain XAdES over it", "auto", map[string]string{},
			[]byte(strings.Replace(invoice, "<FileHeader/>", `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>`, 1)),
			domain.InvalidFacturaE},
	}
	for _, refused := range cases {
		_, err := signPage(t, refused.format, refused.properties, refused.data)
		wantFailure(t, err, refused.want, refused.what)
	}
}

// TestAPolicyByItsPartsForAPage: the page's OID, digest and qualifier.
func TestAPolicyByItsPartsForAPage(t *testing.T) {
	signed, err := signPage(t, "CAdES", map[string]string{
		"policyIdentifier": "urn:oid:1.3.6.1.4.1.99999.1", "policyIdentifierHashAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
		"policyIdentifierHash": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "policyQualifier": "https://sede.example/politica.pdf",
	}, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed.Signature, []byte("https://sede.example/politica.pdf")) {
		t.Error("the page's qualifier is missing")
	}
}

// TestAFacturaEPageSignsTheInvoiceEnveloped with FacturaE 3.1 and the
// issuer's role, or the roles the page names; auto recognises an invoice.
func TestAFacturaEPageSignsTheInvoiceEnveloped(t *testing.T) {
	for _, name := range []string{"FacturaE", "auto"} {
		signed, err := signPage(t, name, map[string]string{}, []byte(invoice))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		output := string(signed.Signature)
		if !strings.Contains(output, "<xades:Identifier>"+facturaE31+"</xades:Identifier>") {
			t.Errorf("%s: not signed with FacturaE 3.1", name)
		}
		if !strings.Contains(output, "<xades:ClaimedRole>emisor</xades:ClaimedRole>") {
			t.Errorf("%s: the issuer's role is missing", name)
		}
		if !strings.Contains(output, "xmldsig#enveloped-signature") || !strings.HasSuffix(strings.TrimSpace(output), "</fe:Facturae>") {
			t.Errorf("%s: an invoice is signed enveloped", name)
		}
	}

	signed, err := signPage(t, "FacturaE", map[string]string{"signerClaimedRoles": "Receptor"}, []byte(invoice))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed.Signature, []byte("<xades:ClaimedRole>Receptor</xades:ClaimedRole>")) {
		t.Error("the page's role is missing")
	}
}

// TestAXAdESPageClaimsSeveralRoles, separated by "|".
func TestAXAdESPageClaimsSeveralRoles(t *testing.T) {
	signed, err := signPage(t, "XAdES", map[string]string{"signerClaimedRoles": "Secretaria|Interventora"}, []byte("<acta/>"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed.Signature, []byte("<xades:ClaimedRole>Secretaria</xades:ClaimedRole><xades:ClaimedRole>Interventora</xades:ClaimedRole>")) {
		t.Error("both roles must be claimed")
	}
}

// TestXAdESWithoutAVariantIsEnveloping, as AutoFirma's XAdES signer
// defaults: the data inside the signature, even when they are XML.
func TestXAdESWithoutAVariantIsEnveloping(t *testing.T) {
	for _, data := range [][]byte{[]byte("<acta/>"), []byte("texto plano")} {
		signed, err := signPage(t, "XAdES", map[string]string{}, data)
		if err != nil {
			t.Fatalf("%s: %v", data, err)
		}
		root := strings.TrimSpace(string(signed.Signature))
		root = root[strings.Index(root, "?>")+2:]
		if !strings.HasPrefix(strings.TrimSpace(root), "<ds:Signature") {
			t.Errorf("%s: not enveloping:\n%.200s", data, root)
		}
	}
	signed, err := signPage(t, "XAdES", map[string]string{"format": "XAdES Enveloped"}, []byte("<acta/>"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signed.Signature), "<acta>") && !strings.Contains(string(signed.Signature), "<acta><ds:Signature") {
		t.Error("format=XAdES Enveloped keeps the document as the root")
	}
}

// TestXAdESDetachedIsAutoFirmasLayout: AFIRMA holds CONTENT and the
// signature, whatever the data; the page receives one file.
func TestXAdESDetachedIsAutoFirmasLayout(t *testing.T) {
	for _, data := range [][]byte{[]byte("%PDF-1.4\n%solicitud\n"), []byte("<solicitud/>")} {
		for _, request := range []struct {
			format     string
			properties map[string]string
		}{
			{"XAdES Detached", map[string]string{}},
			{"XAdES", map[string]string{"format": "XAdES Detached"}},
		} {
			signed, err := signPage(t, request.format, request.properties, data)
			if err != nil {
				t.Fatalf("%s %v: %v", request.format, request.properties, err)
			}
			output := string(signed.Signature)
			afirma := strings.Index(output, "<AFIRMA ")
			content := strings.Index(output, "<CONTENT ")
			signature := strings.Index(output, "<ds:Signature")
			if afirma < 0 || content < afirma || signature < content {
				t.Errorf("%s with %.8q: not AFIRMA/CONTENT then the signature:\n%.300s", request.format, data, output)
			}
		}
	}
}

// TestXMLDSigPages: enveloping by default as AutoFirma, AFIRMA when
// detached, never XAdES properties; a policy or a timestamp is refused.
func TestXMLDSigPages(t *testing.T) {
	for _, request := range []struct {
		format, layout string
		properties     map[string]string
	}{
		{"XMLDSig", "<ds:Signature", map[string]string{"signerClaimedRoles": "emisor"}},
		{"XMLDSig Detached", "<AFIRMA ", map[string]string{}},
		{"XMLDSig", "<AFIRMA ", map[string]string{"format": "XMLDSig Detached"}},
		{"XMLDSig Enveloped", "<acta><ds:Signature", map[string]string{}},
	} {
		signed, err := signPage(t, request.format, request.properties, []byte("<acta/>"))
		if err != nil {
			t.Fatalf("%s %v: %v", request.format, request.properties, err)
		}
		output := string(signed.Signature)
		if !strings.Contains(output, request.layout) || strings.Contains(output, "QualifyingProperties") {
			t.Errorf("%s %v:\n%.300s", request.format, request.properties, output)
		}
	}
	_, err := signPage(t, "XMLDSig", map[string]string{"expPolicy": "FirmaAGE"}, []byte("<acta/>"))
	wantFailure(t, err, domain.InvalidPolicy, "FirmaAGE with XMLDSig")
	_, err = signPage(t, "XMLDSig", map[string]string{"policyIdentifier": "1.2.3.4",
		"policyIdentifierHash": "G7roucf600+f03r/o0bAOQ6WAs0=", "policyIdentifierHashAlgorithm": "SHA1"}, []byte("<acta/>"))
	wantFailure(t, err, domain.InvalidPolicy, "a policy with XMLDSig")
	_, err = signPage(t, "XMLDSig", map[string]string{"tsaURL": "http://tsa.example.invalid"}, []byte("<acta/>"))
	wantFailure(t, err, domain.UnsupportedOperation, "a timestamp with XMLDSig")
}
