package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// TestAContainerIsCoSignedWithTheKindOfSignatureItHolds: an ASiC-S's CAdES
// signature is co-signed in place and its XAdES file takes one more; an
// ASiC-E takes a new signature file over all its documents.
func TestAContainerIsCoSignedWithTheKindOfSignatureItHolds(t *testing.T) {
	documents := []application.ContainerEntry{{Name: "plano.pdf", Content: []byte("%PDF")}, {Name: "memoria.txt", Content: []byte("m")}}
	for name, check := range map[string]struct {
		container domain.Container
		signature application.ContainerEntry
		want      []string
		format    domain.Format
	}{
		"ASiC-S CAdES": {domain.ASiCS, application.ContainerEntry{Name: "META-INF/signature.p7s", Content: []byte("p7s")},
			[]string{"plano.pdf", "memoria.txt", "META-INF/signature.p7s=cades-output"}, domain.Cades},
		"ASiC-S XAdES": {domain.ASiCS, application.ContainerEntry{Name: "META-INF/signatures.xml", Content: []byte("xml")},
			[]string{"plano.pdf", "memoria.txt", "META-INF/signatures.xml=xml+xades-output"}, domain.Xades},
		"ASiC-E XAdES": {domain.ASiCE, application.ContainerEntry{Name: "META-INF/signatures001.xml", Content: []byte("xml")},
			[]string{"plano.pdf", "memoria.txt", "META-INF/signatures001.xml=xml", "META-INF/signatures002.xml=xades-output"}, domain.Xades},
		"ASiC-E CAdES": {domain.ASiCE, application.ContainerEntry{Name: "META-INF/signature001.p7s", Content: []byte("p7s")},
			[]string{"plano.pdf", "memoria.txt", "META-INF/signature001.p7s=p7s",
				"META-INF/ASiCManifest002.xml=manifest META-INF/signature002.p7s plano.pdf memoria.txt", "META-INF/signature002.p7s=cades-output"},
			domain.Cades},
	} {
		store := newFakeStore(map[string][]byte{"/tmp/expediente.asice": []byte("zip")})
		cades, xades := &fakeCades{}, &fakeXades{}
		containers := &fakeContainers{held: check.container, heldEntries: append(append([]application.ContainerEntry{}, documents...), check.signature)}
		useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), cades, &fakePades{}, xades).
			WithContainers(containers)
		artefact, err := useCase.Execute(context.Background(), application.Request{Document: newDocument(t, "/tmp/expediente.asice"),
			Format: domain.Cades, Level: domain.BES, Signer: newSigner(t), Cosign: true, Location: "Sevilla"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got []string
		for _, entry := range containers.entries {
			if strings.HasPrefix(entry.Name, "META-INF/") {
				got = append(got, entry.Name+"="+string(entry.Content))
			} else {
				got = append(got, entry.Name)
			}
		}
		if strings.Join(got, "|") != strings.Join(check.want, "|") || containers.container != check.container ||
			artefact.Path != "/tmp/expediente_cosigned.asice" {
			t.Errorf("%s: %q into %s at %s", name, got, containers.container, artefact.Path)
		}
		// The request asked CAdES; the container's kind is what was signed.
		if artefact.Format != check.format {
			t.Errorf("%s: the artefact says %s, want %s", name, artefact.Format, check.format)
		}
		switch {
		case strings.HasPrefix(name, "ASiC-S CAdES") && (!cades.request.Cosign || string(cades.request.DetachedContent) != "%PDF"):
			t.Errorf("%s: %+v", name, cades.request)
		case strings.Contains(name, "XAdES") && (!xades.request.InASiC || xades.request.Packaging != domain.XMLDetached ||
			len(xades.request.MoreDocuments) != 1 || xades.request.Place.City != "Sevilla"):
			t.Errorf("%s: %+v", name, xades.request)
		case name == "ASiC-E CAdES" && !cades.request.Detached:
			t.Errorf("%s: the signature beside its manifest", name)
		}
	}
}

func TestAContainerWithoutWhatACoSignatureNeedsIsRefused(t *testing.T) {
	for name, containers := range map[string]*fakeContainers{
		"unreadable":   {readErr: errors.New("not a zip")},
		"no document":  {held: domain.ASiCS, heldEntries: []application.ContainerEntry{{Name: "META-INF/signature.p7s"}}},
		"no signature": {held: domain.ASiCS, heldEntries: []application.ContainerEntry{{Name: "plano.pdf"}}},
	} {
		store := newFakeStore(map[string][]byte{"/tmp/plano.pdf.asics": []byte("zip")})
		useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), &fakeCades{}, &fakePades{}, &fakeXades{}).
			WithContainers(containers)
		if _, err := useCase.Execute(context.Background(), application.Request{Document: newDocument(t, "/tmp/plano.pdf.asics"),
			Format: domain.Cades, Level: domain.BES, Signer: newSigner(t), Cosign: true}); err == nil {
			t.Errorf("%s: co-signed", name)
		}
	}
	store := newFakeStore(map[string][]byte{"/tmp/plano.pdf.asics": []byte("zip")})
	withoutContainers := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), &fakeCades{}, &fakePades{}, &fakeXades{})
	if _, err := withoutContainers.Execute(context.Background(), application.Request{Document: newDocument(t, "/tmp/plano.pdf.asics"),
		Format: domain.Cades, Level: domain.BES, Signer: newSigner(t), Cosign: true}); err == nil {
		t.Error("no container adapter")
	}
}

type failingCades struct{}

func (failingCades) SignCades(context.Context, application.CadesRequest) ([]byte, error) {
	return nil, errors.New("the card refused the PIN")
}

type failingXades struct{}

func (failingXades) SignXades(context.Context, application.XadesRequest) ([]byte, error) {
	return nil, errors.New("the card refused the PIN")
}

// TestACoSignatureThatFailsWritesNothing: an adapter's error is the answer.
func TestACoSignatureThatFailsWritesNothing(t *testing.T) {
	documents := []application.ContainerEntry{{Name: "plano.pdf", Content: []byte("%PDF")}}
	p7s := application.ContainerEntry{Name: "META-INF/signature.p7s"}
	xml := application.ContainerEntry{Name: "META-INF/signatures.xml"}
	for name, check := range map[string]struct {
		containers *fakeContainers
		cades      application.CadesSigner
		xades      application.XadesSigner
	}{
		"ASiC-S CAdES": {&fakeContainers{held: domain.ASiCS, heldEntries: append(documents, p7s)}, failingCades{}, &fakeXades{}},
		"ASiC-S XAdES": {&fakeContainers{held: domain.ASiCS, heldEntries: append(documents, xml)}, &fakeCades{}, failingXades{}},
		"ASiC-S XAdES merge": {&fakeContainers{held: domain.ASiCS, heldEntries: append(documents, xml), mergeErr: errors.New("breaks")},
			&fakeCades{}, &fakeXades{}},
		"ASiC-E XAdES": {&fakeContainers{held: domain.ASiCE, heldEntries: append(documents, xml)}, &fakeCades{}, failingXades{}},
		"ASiC-E CAdES": {&fakeContainers{held: domain.ASiCE, heldEntries: append(documents, p7s)}, failingCades{}, &fakeXades{}},
		"ASiC-E CAdES manifest": {&fakeContainers{held: domain.ASiCE, heldEntries: append(documents, p7s), manifestErr: errors.New("no")},
			&fakeCades{}, &fakeXades{}},
	} {
		store := newFakeStore(map[string][]byte{"/tmp/plano.pdf.asics": []byte("zip")})
		useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), check.cades, &fakePades{}, check.xades).
			WithContainers(check.containers)
		if _, err := useCase.Execute(context.Background(), application.Request{Document: newDocument(t, "/tmp/plano.pdf.asics"),
			Format: domain.Cades, Level: domain.BES, Signer: newSigner(t), Cosign: true}); err == nil || len(store.written) != 0 {
			t.Errorf("%s: %v, written %v", name, err, store.written)
		}
	}
}
