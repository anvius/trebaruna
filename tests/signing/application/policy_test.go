package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

const unsignedInvoice = `<?xml version="1.0"?><fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml"><FileHeader/></fe:Facturae>`

// signWithPolicy runs the use case on one file with a policy and a role.
func signWithPolicy(t *testing.T, path string, content string, format domain.Format, enveloping bool,
	policy domain.SignaturePolicy, roles ...string) (*fakeCades, *fakeXades, error) {
	t.Helper()
	cades, xades := &fakeCades{}, &fakeXades{}
	useCase := application.NewSignDocument(newFakeStore(map[string][]byte{path: []byte(content)}),
		fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), cades, &fakePades{}, xades)
	_, err := useCase.Execute(context.Background(), application.Request{
		Document:     newDocument(t, path),
		Format:       format,
		Level:        domain.BES,
		Signer:       newSigner(t),
		Enveloping:   enveloping,
		Policy:       policy,
		ClaimedRoles: roles,
	})
	return cades, xades, err
}

func namedPolicy(t *testing.T, name string, format domain.Format) domain.SignaturePolicy {
	t.Helper()
	policy, err := domain.NamedPolicy(name, format)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// TestThePolicyReachesTheSigner: CAdES gets the policy, XAdES the policy and
// the role.
func TestThePolicyReachesTheSigner(t *testing.T) {
	age := namedPolicy(t, "age", domain.Cades)
	cades, _, err := signWithPolicy(t, "/tmp/a.txt", "text", domain.Cades, false, age)
	if err != nil {
		t.Fatal(err)
	}
	if cades.request.Policy.Identifier() != "2.16.724.1.3.1.1.2.1.9" {
		t.Errorf("CAdES policy %q", cades.request.Policy.Identifier())
	}

	facturae := namedPolicy(t, "facturae", domain.Xades)
	_, xades, err := signWithPolicy(t, "/tmp/f.xml", unsignedInvoice, domain.Xades, false, facturae, "receptor")
	if err != nil {
		t.Fatal(err)
	}
	if !xades.request.Policy.IsFacturaE() || len(xades.request.ClaimedRoles) != 1 || xades.request.ClaimedRoles[0] != "receptor" {
		t.Errorf("XAdES request %+v", xades.request)
	}
}

// TestAFacturaESignatureClaimsTheIssuerUnlessTold, and only FacturaE's roles.
func TestAFacturaESignatureClaimsTheIssuerUnlessTold(t *testing.T) {
	facturae := namedPolicy(t, "facturae", domain.Xades)
	_, xades, err := signWithPolicy(t, "/tmp/f.xml", unsignedInvoice, domain.Xades, false, facturae)
	if err != nil {
		t.Fatal(err)
	}
	if len(xades.request.ClaimedRoles) != 1 || xades.request.ClaimedRoles[0] != "emisor" {
		t.Errorf("roles %v, want emisor", xades.request.ClaimedRoles)
	}

	_, xades, err = signWithPolicy(t, "/tmp/f.xml", unsignedInvoice, domain.Xades, false, facturae, "Notario")
	if !errors.Is(err, domain.ErrInvalidRole) || xades.called {
		t.Errorf("a role FacturaE does not name: %v", err)
	}
}

// TestFacturaEPoliciesSignOnlyUnsignedInvoicesEnveloped mirrors AutoFirma's
// SAF_32 and SAF_38: another document, another format, an enveloping
// signature or a signed invoice are refused before the card is touched.
func TestFacturaEPoliciesSignOnlyUnsignedInvoicesEnveloped(t *testing.T) {
	facturae := namedPolicy(t, "facturae", domain.Xades)
	signed := `<fe:Facturae xmlns:fe="x"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature></fe:Facturae>`
	cases := []struct {
		name       string
		path       string
		content    string
		format     domain.Format
		enveloping bool
	}{
		{"another XML", "/tmp/o.xml", `<ordine/>`, domain.Xades, false},
		{"a signed invoice", "/tmp/s.xml", signed, domain.Xades, false},
		{"enveloping", "/tmp/f.xml", unsignedInvoice, domain.Xades, true},
		{"CAdES", "/tmp/f.xml", unsignedInvoice, domain.Cades, false},
	}
	for _, refused := range cases {
		cades, xades, err := signWithPolicy(t, refused.path, refused.content, refused.format, refused.enveloping, facturae)
		if !errors.Is(err, domain.ErrNotFacturaE) {
			t.Errorf("%s: %v, want ErrNotFacturaE", refused.name, err)
		}
		if cades.called || xades.called {
			t.Errorf("%s: the signer ran", refused.name)
		}
	}
}

// TestARoleOnlyGoesInXAdES.
func TestARoleOnlyGoesInXAdES(t *testing.T) {
	cades, _, err := signWithPolicy(t, "/tmp/a.txt", "text", domain.Cades, false, domain.SignaturePolicy{}, "emisor")
	if err == nil || cades.called {
		t.Fatalf("a CAdES signature claimed a role: %v", err)
	}
}

// TestAURLPolicyIsRefusedForCAdES: only XAdES names a policy by URL.
func TestAURLPolicyIsRefusedForCAdES(t *testing.T) {
	byURL, err := domain.NewSignaturePolicy("https://example.org/policy.pdf", "SHA256",
		"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "")
	if err != nil {
		t.Fatal(err)
	}
	cades, _, err := signWithPolicy(t, "/tmp/a.txt", "text", domain.Cades, false, byURL)
	if !errors.Is(err, domain.ErrPolicyNotForFormat) || cades.called {
		t.Fatalf("%v", err)
	}
}

// TestXMLDSigIsLevelBWithoutPolicy: it has no properties to hold either.
func TestXMLDSigIsLevelBWithoutPolicy(t *testing.T) {
	age := namedPolicy(t, "age", domain.Xades)
	_, xades, err := signWithPolicy(t, "/tmp/a.xml", "<a/>", domain.Xmldsig, false, age)
	if !errors.Is(err, domain.ErrPolicyNotForFormat) || xades.called {
		t.Errorf("a policy in XMLDSig: %v", err)
	}
	useCase := application.NewSignDocument(newFakeStore(map[string][]byte{"/tmp/a.xml": []byte("<a/>")}),
		fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), &fakeCades{}, &fakePades{}, &fakeXades{})
	_, err = useCase.Execute(context.Background(), application.Request{Document: newDocument(t, "/tmp/a.xml"),
		Format: domain.Xmldsig, Level: domain.T, TimestampURL: "http://tsa.example.invalid", Signer: newSigner(t)})
	if err == nil {
		t.Error("XMLDSig at level T must be refused")
	}
	_, xades, err = signWithPolicy(t, "/tmp/a.xml", "<a/>", domain.Xmldsig, false, domain.SignaturePolicy{})
	if err != nil || !xades.called || !xades.request.Plain {
		t.Errorf("plain XMLDSig request: %+v, %v", xades.request, err)
	}
}
