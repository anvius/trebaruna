package application_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// fakeContainers records what is packed.
type fakeContainers struct {
	container domain.Container
	entries   []application.ContainerEntry
	// held is the container ReadContainer finds; readErr fails it.
	held        domain.Container
	heldEntries []application.ContainerEntry
	readErr     error
	// manifestErr and mergeErr fail Manifest and AddXMLSignatures.
	manifestErr, mergeErr error
}

func (f *fakeContainers) ReadContainer([]byte) (domain.Container, []application.ContainerEntry, error) {
	return f.held, append([]application.ContainerEntry{}, f.heldEntries...), f.readErr
}

func (f *fakeContainers) AddXMLSignatures(signatures, added []byte, _ []application.ContainerEntry) ([]byte, error) {
	return []byte(string(signatures) + "+" + string(added)), f.mergeErr
}

func (f *fakeContainers) WriteContainer(container domain.Container, entries []application.ContainerEntry) ([]byte, error) {
	f.container, f.entries = container, entries
	return []byte("zip"), nil
}

// ManifestOf finds the fake manifest naming the signature.
func (f *fakeContainers) ManifestOf(signatureEntry string, entries []application.ContainerEntry) (application.ContainerEntry, bool) {
	for _, entry := range entries {
		if strings.Contains(entry.Name, "ASiCManifest") && strings.HasPrefix(string(entry.Content), "manifest "+signatureEntry) {
			return entry, true
		}
	}
	return application.ContainerEntry{}, false
}

func (f *fakeContainers) Manifest(signatureEntry string, documents []application.ContainerEntry) ([]byte, error) {
	if f.manifestErr != nil {
		return nil, f.manifestErr
	}
	manifest := "manifest " + signatureEntry
	for _, document := range documents {
		manifest += " " + document.Name
	}
	return []byte(manifest), nil
}

// TestAnASiCSHoldsTheDocumentAndItsDetachedSignature.
func TestAnASiCSHoldsTheDocumentAndItsDetachedSignature(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/informe.pdf": []byte("%PDF")})
	cades, xades, containers := &fakeCades{}, &fakeXades{}, &fakeContainers{}
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), cades, &fakePades{}, xades).
		WithContainers(containers)
	execute := func(format domain.Format, container domain.Container, extra func(*application.Request)) (application.Artefact, error) {
		request := application.Request{Document: newDocument(t, "/tmp/informe.pdf"), Format: format, Level: domain.BES,
			Signer: newSigner(t), Container: container}
		if extra != nil {
			extra(&request)
		}
		return useCase.Execute(context.Background(), request)
	}

	artefact, err := execute(domain.Cades, domain.ASiCS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if artefact.Path != "/tmp/informe.pdf.asics" || string(store.written[artefact.Path]) != "zip" || !cades.request.Detached {
		t.Errorf("artefact %+v, detached %v", artefact, cades.request.Detached)
	}
	if len(containers.entries) != 2 || containers.entries[0].Name != "informe.pdf" || containers.entries[1].Name != "META-INF/signature.p7s" {
		t.Errorf("entries %+v", containers.entries)
	}

	if _, err := execute(domain.Xades, domain.ASiCS, nil); err != nil {
		t.Fatal(err)
	}
	if !xades.request.InASiC || xades.request.Packaging != domain.XMLDetached || containers.entries[1].Name != "META-INF/signatures.xml" {
		t.Errorf("XAdES in a container: %+v", xades.request)
	}

	for what, refused := range map[string]func() error{
		"PAdES": func() error { _, err := execute(domain.Pades, domain.ASiCS, nil); return err },
		"co-sign": func() error {
			_, err := execute(domain.Cades, domain.ASiCS, func(r *application.Request) { r.Cosign = true })
			return err
		},
		"enveloping": func() error {
			_, err := execute(domain.Xades, domain.ASiCS, func(r *application.Request) { r.Enveloping = true })
			return err
		},
	} {
		if refused() == nil {
			t.Errorf("%s into a container was accepted", what)
		}
	}
}

// TestAnASiCEHoldsEveryDocumentUnderOneSignature: XAdES references each,
// CAdES signs a manifest of them.
func TestAnASiCEHoldsEveryDocumentUnderOneSignature(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/acta.txt": []byte("acta"), "/tmp/anexos/plano.pdf": []byte("%PDF")})
	cades, xades, containers := &fakeCades{}, &fakeXades{}, &fakeContainers{}
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), cades, &fakePades{}, xades).
		WithContainers(containers)
	execute := func(format domain.Format, container domain.Container, more ...string) (application.Artefact, error) {
		var others []domain.Document
		for _, path := range more {
			others = append(others, newDocument(t, path))
		}
		return useCase.Execute(context.Background(), application.Request{Document: newDocument(t, "/tmp/acta.txt"), Format: format,
			Level: domain.BES, Signer: newSigner(t), Container: container, MoreDocuments: others})
	}

	artefact, err := execute(domain.Xades, domain.ASiCE, "/tmp/anexos/plano.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if artefact.Path != "/tmp/acta.txt.asice" || len(xades.request.MoreDocuments) != 1 || xades.request.MoreDocuments[0].Name != "plano.pdf" {
		t.Errorf("XAdES ASiC-E: %s %+v", artefact.Path, xades.request.MoreDocuments)
	}
	names := func() string {
		var list []string
		for _, entry := range containers.entries {
			list = append(list, entry.Name)
		}
		return fmt.Sprint(list)
	}
	if names() != "[acta.txt plano.pdf META-INF/signatures.xml]" {
		t.Errorf("XAdES entries %s", names())
	}

	if _, err := execute(domain.Cades, domain.ASiCE, "/tmp/anexos/plano.pdf"); err != nil {
		t.Fatal(err)
	}
	if string(cades.request.Content) != "manifest META-INF/signature.p7s acta.txt plano.pdf" || !cades.request.Detached {
		t.Errorf("CAdES signs the manifest: %q", cades.request.Content)
	}
	if names() != "[acta.txt plano.pdf META-INF/ASiCManifest.xml META-INF/signature.p7s]" {
		t.Errorf("CAdES entries %s", names())
	}

	store.files["/tmp/otra/acta.txt"] = []byte("otra")
	for what, refused := range map[string]func() error{
		"a name twice":            func() error { _, err := execute(domain.Cades, domain.ASiCE, "/tmp/otra/acta.txt"); return err },
		"two documents in ASiC-S": func() error { _, err := execute(domain.Cades, domain.ASiCS, "/tmp/anexos/plano.pdf"); return err },
		"two without a container": func() error { _, err := execute(domain.Cades, domain.NoContainer, "/tmp/anexos/plano.pdf"); return err },
	} {
		if refused() == nil {
			t.Errorf("%s was accepted", what)
		}
	}
}
