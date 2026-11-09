package infrastructure_test

// signatureField: a page names the form's empty field to sign in, as in
// AutoFirma; the position keys then do not apply, and a name the form
// lacks is refused.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/pdffield"
	"codeberg.org/simplicer/trebaruna/tests/support/afirmaserver"
)

// formWithField is onePagePDF with an empty signature field, Firma1.
func formWithField() []byte {
	form := string(onePagePDF())
	form = strings.Replace(form, "<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] >> >>", 1)
	form = strings.Replace(form, "/MediaBox [0 0 595 842] >>", "/MediaBox [0 0 595 842] /Annots [4 0 R] >>", 1)
	body := form[:strings.Index(form, "xref\n")]
	body += "4 0 obj\n<< /FT /Sig /T (Firma1) /Type /Annot /Subtype /Widget /Rect [300 100 500 160] /P 3 0 R /F 4 >>\nendobj\n"
	var out strings.Builder
	out.WriteString(body)
	out.WriteString("xref\n0 5\n0000000000 65535 f \n")
	for id := 1; id <= 4; id++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", strings.Index(body, fmt.Sprintf("\n%d 0 obj", id))+1)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(body))
	return []byte(out.String())
}

func TestAPageSignsInTheFormsField(t *testing.T) {
	signed, err := signPage(t, "PAdES", map[string]string{"signatureField": "Firma1",
		"signaturePositionOnPageLowerLeftX": "10", "signaturePositionOnPageLowerLeftY": "10",
		"signaturePositionOnPageUpperRightX": "200", "signaturePositionOnPageUpperRightY": "60"}, formWithField())
	if err != nil {
		t.Fatal(err)
	}
	fields, err := pdffield.EmptyFields(signed.Signature)
	if err != nil || len(fields) != 0 || strings.Count(string(signed.Signature), "/Type /Sig ") != 1 {
		t.Errorf("Firma1 holds the one signature: empty fields %v, %v", fields, err)
	}

	_, err = signPage(t, "PAdES", map[string]string{"signatureField": "Firma9"}, formWithField())
	wantFailure(t, err, domain.SignatureFailed, "a field the form lacks")
}

// TestAnXAdESPageIsCoSignedAndCounterSigned: a co-signature signs the
// signed XML again, a counter-signature (target "tree": all) goes inside
// the signatures it signs.
func TestAnXAdESPageIsCoSignedAndCounterSigned(t *testing.T) {
	maria, _ := identity(t, "MARIA GARCIA", 31)
	signer := infrastructure.NewNativePageSigner()
	signed, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Sign, Format: format(t, "XAdES Enveloped"),
		Algorithm: "SHA256", Properties: map[string]string{}, Data: []byte("<solicitud/>"), Key: maria})
	if err != nil {
		t.Fatal(err)
	}
	cosigned, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Cosign, Format: format(t, "auto"),
		Algorithm: "SHA256", Properties: map[string]string{}, Data: signed.Signature, Key: maria})
	if err != nil {
		t.Fatal(err)
	}
	countersigned, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Countersign, Format: format(t, "auto"),
		Algorithm: "SHA256", Properties: map[string]string{"target": "tree"}, Data: cosigned.Signature, Key: maria})
	if err != nil {
		t.Fatal(err)
	}
	output := string(countersigned.Signature)
	if strings.Count(output, "<ds:Signature ") != 4 || strings.Count(output, "<xades:CounterSignature") != 2 {
		t.Errorf("two signatures, each counter-signed:\n%.400s", output)
	}
}

// TestThePersonSeesWhatTheSignatureWillDeclare: the policy, the roles and
// the place the page asks for are in the proposal, and the XAdES signature
// declares the place.
func TestThePersonSeesWhatTheSignatureWillDeclare(t *testing.T) {
	server := afirmaserver.New(t)
	maria, _ := identity(t, "MARIA GARCIA", 61)
	id, key := sessionID(), "11223344"
	properties := base64.StdEncoding.EncodeToString([]byte("expPolicy=FirmaAGE\nsignerClaimedRoles=Apoderado|Notario\n" +
		"signatureProductionCity=Sevilla\nsignatureProductionCountry=ES\nformat=XAdES Enveloped"))
	uri := "afirma://sign?jvc=3&ver=3&op=sign&id=" + id + "&key=" + key + "&stservlet=" + url.QueryEscape(storage) +
		"&format=XAdES&algorithm=SHA256withECDSA&properties=" + url.QueryEscape(properties) +
		"&dat=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("<solicitud/>")))
	invocation, err := domain.ParseInvocation(uri)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &proposalRecorder{approving: approving{key: maria}}
	if _, err := useCase(server, recorder).Execute(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	if proposal := recorder.proposal; proposal.Policy != "AGE 1.9" || strings.Join(proposal.Roles, "|") != "Apoderado|Notario" || proposal.Place != "Sevilla, ES" {
		t.Errorf("the proposal: %+v", proposal)
	}
	signed := pageReads(t, server, id, key)[1]
	if !strings.Contains(string(signed), "<xades:City>Sevilla</xades:City><xades:CountryName>ES</xades:CountryName>") {
		t.Error("the signature declares the place")
	}
}
