package integration_test

// EPES signatures: the policy must be where an independent reader looks for
// it (openssl's attribute names for CAdES, the XAdES 1.3.2 order for XML),
// and the signature must still verify with it.

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
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

	// verify reads it back.
	reports, err := verificationinfra.NewCadesVerifier().Extract(path)
	if err != nil || len(reports) != 1 || reports[0].Declared.PolicyName() != "AGE 1.9" {
		t.Errorf("verify reads the policy: %+v %v", reports, err)
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

	// verify reads them back.
	path := filepath.Join(t.TempDir(), "solicitud.xml")
	if err := os.WriteFile(path, output, 0o600); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil || len(reports) != 1 {
		t.Fatalf("%v %v", reports, err)
	}
	if declared := reports[0].Declared; declared.PolicyText() != "AGE 1.9 (2.16.724.1.3.1.1.2.1.9)" ||
		strings.Join(declared.Roles, "|") != "Jefe de <servicio>|Notario" {
		t.Errorf("verify reads %+v", declared)
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

// TestPadesDeclaresTheAGEPolicy: a PDF signature with a policy is written
// by trebaruna (the PDF library cannot add the attribute), in a new field
// with one seal per placement (the second page's annotations an object of
// their own) or in a form's field. openssl checks each envelope over the
// signed byte ranges and finds the policy; the PDF verifier the document.
func TestPadesDeclaresTheAGEPolicy(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	age, err := domain.NamedPolicy("age", domain.Pades)
	if err != nil {
		t.Fatal(err)
	}
	twoPages := []byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n" +
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> >>\nendobj\n" +
		"4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] /Resources << >> /Annots 5 0 R >>\nendobj\n" +
		"5 0 obj\n[]\nendobj\n")
	twoPages = append(twoPages, crossReferences(twoPages, 5)...)

	for name, request := range map[string]application.PadesRequest{
		"a new field, the default seal": {Content: blankPDFBytes(), Placements: []domain.SealPlacement{domain.DefaultSeal(1)}},
		"a new field, invisible":        {Content: blankPDFBytes()},
		"two seals on two pages": {Content: twoPages, Placements: []domain.SealPlacement{
			mustPlacement(t, 1, 400, 700, 560, 750), mustPlacement(t, 2, 600, 60, 780, 110)}},
		"a form's field": {Content: formPDF(false, false), Field: "form.Firma2"},
	} {
		request.Signer, request.Level, request.Policy, request.SignedAt = signer, domain.BES, age, timeNow()
		signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), request)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		reports := verifyPDF(t, newLocalTSA(t), signed)
		if len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood || reports[0].Declared.PolicyName() != "AGE 1.9" {
			t.Errorf("%s: %+v", name, reports)
		}
		envelope, covered := lastEnvelope(t, signed)
		directory := t.TempDir()
		envelopePath, coveredPath := filepath.Join(directory, "signature.p7s"), filepath.Join(directory, "covered.bin")
		os.WriteFile(envelopePath, envelope, 0o600)
		os.WriteFile(coveredPath, covered, 0o600)
		verify := exec.Command("openssl", "cms", "-verify", "-binary", "-in", envelopePath, "-inform", "DER", "-content", coveredPath,
			"-CAfile", fixture.certPath, "-purpose", "any", "-cades", "-out", os.DevNull)
		if output, err := verify.CombinedOutput(); err != nil {
			t.Errorf("%s: openssl refused the envelope: %v\n%s", name, err, output)
		}
		printed, _ := exec.Command("openssl", "cms", "-cmsout", "-print", "-in", envelopePath, "-inform", "DER").CombinedOutput()
		if !strings.Contains(string(printed), "2.16.724.1.3.1.1.2.1.9") || strings.Contains(string(printed), "signingTime") {
			t.Errorf("%s: the envelope does not declare the AGE policy, or declares a signing time", name)
		}
	}
}

// mustPlacement is a seal box on a page.
func mustPlacement(t *testing.T, page int, left, bottom, right, top float64) domain.SealPlacement {
	t.Helper()
	placement, err := domain.PlaceSeal(page, left, bottom, right, top)
	if err != nil {
		t.Fatal(err)
	}
	return placement
}

// crossReferences closes a PDF body of objects 1..count with a table.
func crossReferences(body []byte, count int) []byte {
	var out strings.Builder
	start := len(body)
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", count+1)
	for id := 1; id <= count; id++ {
		offset := strings.Index(string(body), fmt.Sprintf("\n%d 0 obj", id)) + 1
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", count+1, start)
	return []byte(out.String())
}

// lastEnvelope reads the last signature's CMS envelope and the bytes its
// /ByteRange covers.
func lastEnvelope(t *testing.T, signed []byte) ([]byte, []byte) {
	t.Helper()
	ranges := regexp.MustCompile(`/ByteRange \[0 (\d+) (\d+) (\d+)\s*\]`).FindAllSubmatch(signed, -1)
	if len(ranges) == 0 {
		t.Fatal("no /ByteRange")
	}
	last := ranges[len(ranges)-1]
	start, _ := strconv.Atoi(string(last[1]))
	end, _ := strconv.Atoi(string(last[2]))
	length, _ := strconv.Atoi(string(last[3]))
	hexed := strings.TrimRight(string(signed[start+1:end-1]), "0")
	if len(hexed)%2 == 1 {
		hexed += "0"
	}
	envelope, err := hex.DecodeString(hexed)
	if err != nil {
		t.Fatal(err)
	}
	var envelopeDER asn1.RawValue
	if _, err := asn1.Unmarshal(envelope, &envelopeDER); err == nil {
		envelope = envelopeDER.FullBytes
	}
	return envelope, append(append([]byte{}, signed[:start]...), signed[end:end+length]...)
}
