package integration_test

// EPES signatures: the policy must be where an independent reader looks for
// it (openssl's attribute names for CAdES, the XAdES 1.3.2 order for XML),
// and the signature must still verify with it.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// TestCadesDeclaresTheAGEPolicy: openssl verifies the signature and prints
// the policy attribute with AutoFirma's OID, digest and qualifier.
func TestCadesDeclaresTheAGEPolicy(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	age, err := domain.NamedPolicy("age", domain.Cades)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := infrastructure.NewCadesSigner(nil).SignCades(context.Background(), application.CadesRequest{
		Content: []byte("solicitud\n"),
		Signer:  signer,
		Level:   domain.BES,
		Policy:  age,
	})
	if err != nil {
		t.Fatalf("SignCades: %v", err)
	}
	path := filepath.Join(fixture.directory, "solicitud.txt.p7m")
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatal(err)
	}

	verify := exec.Command("openssl", "cms", "-verify", "-in", path, "-inform", "DER",
		"-CAfile", fixture.certPath, "-purpose", "any", "-cades", "-out", os.DevNull)
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("openssl refused the EPES signature: %v\n%s", err, output)
	}

	printed, err := exec.Command("openssl", "cms", "-cmsout", "-print", "-in", path, "-inform", "DER").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -print: %v\n%s", err, printed)
	}
	dump := string(printed)
	for _, expected := range []string{
		"id-smime-aa-ets-sigPolicyId",
		"2.16.724.1.3.1.1.2.1.9",
		"https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
		"id-smime-spq-ets-sqt-uri",
	} {
		if !strings.Contains(dump, expected) {
			t.Errorf("the signed attributes lack %q", expected)
		}
	}
	// G7roucf600+f03r/o0bAOQ6WAs0= in the hexadecimal dump openssl prints.
	if !strings.Contains(dump, "1BBAE8B9C7FAD34F9FD37AFFA346C0390E9602CD") {
		t.Error("the policy digest is not AutoFirma's")
	}
}

// TestCosigningKeepsThePolicy: an added signature declares it too.
func TestCosigningKeepsThePolicy(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	age, _ := domain.NamedPolicy("age", domain.Cades)

	first, err := infrastructure.NewCadesSigner(nil).SignCades(context.Background(), application.CadesRequest{
		Content: []byte("acta\n"), Signer: signer, Level: domain.BES, Policy: age,
	})
	if err != nil {
		t.Fatal(err)
	}
	both, err := infrastructure.NewCadesSigner(nil).SignCades(context.Background(), application.CadesRequest{
		Content: first, Signer: signer, Level: domain.BES, Policy: age, Cosign: true,
	})
	if err != nil {
		t.Fatalf("co-sign: %v", err)
	}
	path := filepath.Join(fixture.directory, "acta.txt.p7m")
	if err := os.WriteFile(path, both, 0o600); err != nil {
		t.Fatal(err)
	}
	printed, err := exec.Command("openssl", "cms", "-cmsout", "-print", "-in", path, "-inform", "DER").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -print: %v\n%s", err, printed)
	}
	if count := strings.Count(string(printed), "id-smime-aa-ets-sigPolicyId"); count != 2 {
		t.Errorf("%d signatures declare the policy, want 2", count)
	}
}

// TestXadesDeclaresThePolicyAndTheRole: SignaturePolicyIdentifier follows
// SigningCertificateV2 and precedes SignerRoleV2, the XAdES 1.3.2 order; an
// OID is written as AutoFirma writes it.
func TestXadesDeclaresThePolicyAndTheRole(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	age, _ := domain.NamedPolicy("age", domain.Xades)

	request := buildXadesRequest(signer, []byte(`<solicitud/>`), false)
	request.Policy = age
	request.ClaimedRoles = []string{"Jefe de <servicio>", "Notario"}
	output, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), request)
	if err != nil {
		t.Fatalf("SignXades: %v", err)
	}
	signed := string(output)

	order := []string{"<xades:SigningTime>", "<xades:SigningCertificateV2>", "<xades:SignaturePolicyIdentifier>",
		"<xades:SignerRoleV2>", "</xades:SignedSignatureProperties>"}
	position := -1
	for _, element := range order {
		index := strings.Index(signed, element)
		if index < position {
			t.Fatalf("%s is missing or out of order", element)
		}
		position = index
	}
	for _, expected := range []string{
		`<xades:Identifier Qualifier="OIDAsURN">urn:oid:2.16.724.1.3.1.1.2.1.9</xades:Identifier>`,
		`<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>G7roucf600+f03r/o0bAOQ6WAs0=</ds:DigestValue>`,
		`<xades:SPURI>https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf</xades:SPURI>`,
		`<xades:ClaimedRoles><xades:ClaimedRole>Jefe de &lt;servicio&gt;</xades:ClaimedRole><xades:ClaimedRole>Notario</xades:ClaimedRole></xades:ClaimedRoles>`,
	} {
		if !strings.Contains(signed, expected) {
			t.Errorf("the signature lacks %s", expected)
		}
	}
}

// TestFacturaENamesItsPolicyByURL: no OID qualifier and no SPURI, as
// AutoFirma signs invoices.
func TestFacturaENamesItsPolicyByURL(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	facturae, _ := domain.NamedPolicy("facturae", domain.Xades)

	request := buildXadesRequest(signer, []byte(`<fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml"/>`), false)
	request.Policy = facturae
	request.ClaimedRoles = []string{"emisor"}
	output, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), request)
	if err != nil {
		t.Fatalf("SignXades: %v", err)
	}
	signed := string(output)
	if !strings.Contains(signed, `<xades:Identifier>http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf</xades:Identifier>`) {
		t.Error("FacturaE 3.1 is not named by its URL")
	}
	if strings.Contains(signed, "SigPolicyQualifiers") || strings.Contains(signed, "OIDAsURN") {
		t.Error("FacturaE declares neither a qualifier nor an OID")
	}
}

// TestPadesRefusesAPolicy: the PDF signer cannot add the attribute yet, and
// signing without the policy asked for would mislead.
func TestPadesRefusesAPolicy(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	age, _ := domain.NamedPolicy("age", domain.Pades)

	_, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content: blankPDFBytes(), Signer: signer, Level: domain.BES, Policy: age,
	})
	if !errors.Is(err, domain.ErrPolicyNotForFormat) {
		t.Fatalf("err = %v, want ErrPolicyNotForFormat", err)
	}
}
