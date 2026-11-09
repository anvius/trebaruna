package integration_test

// Co-signing an ASiC-S whose signatures file is XAdES: the new signature
// joins the others in META-INF/signatures.xml, and the verifier reads both;
// a root whose namespaces would change the new signature's canonical form
// is refused instead of written broken. The use case's other kinds were
// judged by hand: openssl verifies an ASiC-S CAdES co-signed in place,
// xmlsec1 each signature of an ASiC-S XAdES, verify all four kinds.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func TestAnASiCSXadesFileTakesAnotherSignature(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	document := application.ContainerEntry{Name: "plano.pdf", Content: []byte("%PDF-1.4 plano")}
	detached := func() []byte {
		t.Helper()
		signed, err := infrastructure.NewXadesSigner(nil).SignXades(t.Context(), application.XadesRequest{Content: document.Content,
			DocumentName: document.Name, InASiC: true, Packaging: domain.XMLDetached, Signer: signer, Level: domain.BES})
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	containers := infrastructure.AsicContainers{}
	first, second := detached(), detached()

	merged, err := containers.AddXMLSignatures(first, second, []application.ContainerEntry{document})
	if err != nil {
		t.Fatal(err)
	}
	container, err := containers.WriteContainer(domain.ASiCS, []application.ContainerEntry{document, {Name: "META-INF/signatures.xml", Content: merged}})
	if err != nil {
		t.Fatal(err)
	}
	kind, entries, err := containers.ReadContainer(container)
	if err != nil || kind != domain.ASiCS || len(entries) != 2 || entries[0].Name != "plano.pdf" {
		t.Fatalf("read back: %s %v %v", kind, entries, err)
	}
	path := filepath.Join(t.TempDir(), "plano.pdf.asics")
	if err := os.WriteFile(path, container, 0o600); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewAsicVerifier(verificationinfra.NewCadesVerifier(), verificationinfra.NewXadesVerifier()).Extract(path)
	if err != nil || len(reports) != 2 {
		t.Fatalf("%v %v", reports, err)
	}
	for _, report := range reports {
		if report.Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %s", report.FieldName, report.Integrity)
		}
	}

	otherRoot := bytes.Replace(first, []byte("<asic:XAdESSignatures "), []byte(`<asic:XAdESSignatures xmlns:sede="urn:sede" `), 1)
	if bytes.Equal(otherRoot, first) {
		t.Fatal("the root was not found")
	}
	if _, err := containers.AddXMLSignatures(otherRoot, second, []application.ContainerEntry{document}); err == nil {
		t.Error("a root that changes the new signature's canonical form must be refused")
	}
}
