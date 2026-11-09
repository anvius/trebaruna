package cli_test

import (
	"os"
	"strings"
	"testing"
)

// TestSignDeclaresANamedPolicy: --policy age reaches the envelope and the
// signature still verifies.
func TestSignDeclaresANamedPolicy(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeDocument(t, "solicitud.txt", "solicitud\n")

	if _, stderr, code := run("sign", document, "--p12", key, "--format", "cades", "--policy", "age"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	envelope, err := os.ReadFile(document + ".p7m")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(envelope), "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf") {
		t.Error("the envelope does not carry the AGE policy's qualifier")
	}
	if result := verifyJSON(t, document+".p7m"); result.Signers[0].Integrity != "good" {
		t.Errorf("integrity %s", result.Signers[0].Integrity)
	}
}

// TestFacturaEClaimsTheIssuerRoleByDefault, as AutoFirma does.
func TestFacturaEClaimsTheIssuerRoleByDefault(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	invoice := writeDocument(t, "factura.xml",
		`<fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml"><FileHeader/></fe:Facturae>`)

	if _, stderr, code := run("sign", invoice, "--p12", key, "--format", "xades", "--policy", "facturae"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	signed, err := os.ReadFile(strings.TrimSuffix(invoice, ".xml") + "_signed.xml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signed), "<xades:ClaimedRole>emisor</xades:ClaimedRole>") {
		t.Error("a FacturaE signature claims the issuer role unless told otherwise")
	}
}

// TestThePolicyFlagsRefuseNonsense.
func TestThePolicyFlagsRefuseNonsense(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeDocument(t, "a.txt", "a\n")

	for _, arguments := range [][]string{
		{"--policy", "galicia"},
		{"--policy", "age", "--policy-id", "1.2.3"},
		{"--policy-id", "1.2.3", "--policy-hash", "G7roucf600+f03r/o0bAOQ6WAs0=", "--policy-hash-alg", "SHA-256"},
		{"--role", "emisor"},
	} {
		_, _, code := run(append([]string{"sign", document, "--p12", key, "--format", "cades"}, arguments...)...)
		if code == 0 {
			t.Errorf("%v was accepted", arguments)
		}
	}
	if _, err := os.Stat(document + ".p7m"); err == nil {
		t.Error("a refused signature left a file")
	}
}
