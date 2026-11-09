package domain_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// TestTheSpanishPoliciesAreAutoFirmas: the AGE 1.9 digest is the SHA-1 of the
// document published at its qualifier.
func TestTheSpanishPoliciesAreAutoFirmas(t *testing.T) {
	age, err := domain.NamedPolicy("age", domain.Cades)
	if err != nil {
		t.Fatal(err)
	}
	if oid, ok := age.OID(); !ok || oid.String() != "2.16.724.1.3.1.1.2.1.9" {
		t.Errorf("AGE OID %v", oid)
	}
	if base64.StdEncoding.EncodeToString(age.Hash()) != "G7roucf600+f03r/o0bAOQ6WAs0=" || age.HashAlgorithm() != "SHA1" {
		t.Errorf("AGE digest %x", age.Hash())
	}
	xades18, _ := domain.NamedPolicy("FirmaAGE18", domain.Xades)
	cades18, _ := domain.NamedPolicy("age18", domain.Cades)
	if base64.StdEncoding.EncodeToString(xades18.Hash()) == base64.StdEncoding.EncodeToString(cades18.Hash()) {
		t.Error("AGE 1.8 has one digest for XAdES and another for CAdES/PAdES")
	}
	facturae, _ := domain.NamedPolicy("facturae", domain.Xades)
	if facturae.Identifier() != "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf" ||
		base64.StdEncoding.EncodeToString(facturae.Hash()) != "Ohixl6upD6av8N7pEvDABhEL6hM=" {
		t.Errorf("FacturaE 3.1 %q", facturae.Identifier())
	}
	if _, err := domain.NamedPolicy("galicia", domain.Cades); !errors.Is(err, domain.ErrUnknownPolicy) {
		t.Errorf("unknown name: %v", err)
	}
}

// TestAURLPolicyOnlyFitsXAdES: CAdES and PAdES carry an OID.
func TestAURLPolicyOnlyFitsXAdES(t *testing.T) {
	facturae, _ := domain.NamedPolicy("facturae", domain.Xades)
	if err := facturae.FitsFormat(domain.Xades); err != nil {
		t.Errorf("XAdES: %v", err)
	}
	if err := facturae.FitsFormat(domain.Cades); !errors.Is(err, domain.ErrPolicyNotForFormat) {
		t.Errorf("CAdES: %v", err)
	}
	age, _ := domain.NamedPolicy("age", domain.Pades)
	if err := age.FitsFormat(domain.Pades); err != nil {
		t.Errorf("PAdES with an OID: %v", err)
	}
}

// TestAPolicyFromItsParts.
func TestAPolicyFromItsParts(t *testing.T) {
	built, err := domain.NewSignaturePolicy("urn:oid:2.16.724.1.3.1.1.2.1.9", "http://www.w3.org/2000/09/xmldsig#sha1",
		"G7roucf600+f03r/o0bAOQ6WAs0=", "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf")
	if err != nil || built.Identifier() != "2.16.724.1.3.1.1.2.1.9" || built.HashAlgorithm() != "SHA1" {
		t.Fatalf("%+v, %v", built, err)
	}
	for _, parts := range [][4]string{
		{"", "SHA1", "AAAA", ""},
		{"1.2.3", "MD5", "AAAA", ""},
		{"1.2.3", "SHA-256", "not base64!", ""},
		{"1.2.3", "SHA-256", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "not a url"},
		{"1.2.3", "SHA-256", "G7roucf600+f03r/o0bAOQ6WAs0=", ""}, // a SHA-1 digest
	} {
		if _, err := domain.NewSignaturePolicy(parts[0], parts[1], parts[2], parts[3]); !errors.Is(err, domain.ErrInvalidPolicy) {
			t.Errorf("%v: %v", parts, err)
		}
	}
}

// TestFacturaEAcceptsOnlyItsOwnPolicies: 3.1 by default, 3.0 or 3.1 when
// named exactly, nothing else.
func TestFacturaEAcceptsOnlyItsOwnPolicies(t *testing.T) {
	chosen, err := domain.FacturaEPolicy(domain.SignaturePolicy{})
	if err != nil || !strings.HasSuffix(chosen.Identifier(), "v3_1.pdf") {
		t.Fatalf("default %q, %v", chosen.Identifier(), err)
	}
	old, _ := domain.NewSignaturePolicy("http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf",
		"SHA1", "xmfh8D/Ec/hHeE1IB4zPd61zHIY=", "")
	if chosen, err := domain.FacturaEPolicy(old); err != nil || !strings.HasSuffix(chosen.Identifier(), "v3_0.pdf") {
		t.Errorf("3.0: %q, %v", chosen.Identifier(), err)
	}
	wrongDigest, _ := domain.NewSignaturePolicy("http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
		"SHA1", "G7roucf600+f03r/o0bAOQ6WAs0=", "")
	if _, err := domain.FacturaEPolicy(wrongDigest); !errors.Is(err, domain.ErrInvalidPolicy) {
		t.Errorf("3.1 with another digest: %v", err)
	}
	age, _ := domain.NamedPolicy("age", domain.Xades)
	if _, err := domain.FacturaEPolicy(age); !errors.Is(err, domain.ErrInvalidPolicy) {
		t.Errorf("AGE for an invoice: %v", err)
	}
}

// TestFacturaERoles: emisor by default; the policy's roles in either language.
func TestFacturaERoles(t *testing.T) {
	if roles, err := domain.FacturaERoles(nil); err != nil || len(roles) != 1 || roles[0] != "emisor" {
		t.Errorf("default %v, %v", roles, err)
	}
	if _, err := domain.FacturaERoles([]string{"Receptor", "third party"}); err != nil {
		t.Errorf("allowed roles: %v", err)
	}
	if _, err := domain.FacturaERoles([]string{"notario"}); !errors.Is(err, domain.ErrInvalidRole) {
		t.Errorf("notario: %v", err)
	}
}

// TestAnInvoiceIsKnownByItsRoot, signed or not, whatever its namespace prefix.
func TestAnInvoiceIsKnownByItsRoot(t *testing.T) {
	for content, want := range map[string]bool{
		`<?xml version="1.0"?><fe:Facturae xmlns:fe="x"/>`: true,
		`<Facturae><ds:Signature/></Facturae>`:             true,
		`<pedido/>`:                                        false,
		`not xml`:                                          false,
	} {
		if got := domain.IsFacturaEInvoice([]byte(content)); got != want {
			t.Errorf("%s: %t", content, got)
		}
	}
}
