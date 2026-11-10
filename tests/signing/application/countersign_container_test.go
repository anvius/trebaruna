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

// countingCades counter-signs every CAdES file it is given, recording each
// request; failWith fails it.
type countingCades struct {
	requests []application.CadesRequest
	failWith error
}

func (f *countingCades) SignCades(_ context.Context, request application.CadesRequest) ([]byte, error) {
	f.requests = append(f.requests, request)
	return []byte(string(request.Content) + "+countersigned"), f.failWith
}

// countingXades does the same for XAdES signatures files.
type countingXades struct{ requests []application.XadesRequest }

func (f *countingXades) SignXades(_ context.Context, request application.XadesRequest) ([]byte, error) {
	f.requests = append(f.requests, request)
	return []byte(string(request.Content) + "+countersigned"), nil
}

// TestEverySignatureFileOfAContainerIsCounterSigned where it is: CMS
// counter-signatures in a .p7s (with what it signs, for an archive
// timestamp), XAdES ones in a signatures file; the documents untouched.
func TestEverySignatureFileOfAContainerIsCounterSigned(t *testing.T) {
	documents := []application.ContainerEntry{{Name: "plano.pdf", Content: []byte("%PDF")}, {Name: "memoria.txt", Content: []byte("m")}}
	for name, check := range map[string]struct {
		container  domain.Container
		signatures []application.ContainerEntry
		want       []string
		format     domain.Format
		// signs is what each CAdES file signs, in order.
		signs []string
	}{
		"ASiC-S CAdES": {domain.ASiCS, []application.ContainerEntry{{Name: "META-INF/signature.p7s", Content: []byte("p7s")}},
			[]string{"META-INF/signature.p7s=p7s+countersigned"}, domain.Cades, []string{"%PDF"}},
		"ASiC-S XAdES": {domain.ASiCS, []application.ContainerEntry{{Name: "META-INF/signatures.xml", Content: []byte("xml")}},
			[]string{"META-INF/signatures.xml=xml+countersigned"}, domain.Xades, nil},
		"ASiC-E XAdES": {domain.ASiCE, []application.ContainerEntry{{Name: "META-INF/signatures001.xml", Content: []byte("one")},
			{Name: "META-INF/signatures002.xml", Content: []byte("two")}},
			[]string{"META-INF/signatures001.xml=one+countersigned", "META-INF/signatures002.xml=two+countersigned"}, domain.Xades, nil},
		"ASiC-E CAdES": {domain.ASiCE, []application.ContainerEntry{
			{Name: "META-INF/ASiCManifest002.xml", Content: []byte("manifest META-INF/signature002.p7s plano.pdf")},
			{Name: "META-INF/ASiCManifest001.xml", Content: []byte("manifest META-INF/signature001.p7s plano.pdf memoria.txt")},
			{Name: "META-INF/signature001.p7s", Content: []byte("first")}, {Name: "META-INF/signature002.p7s", Content: []byte("second")}},
			[]string{"META-INF/ASiCManifest002.xml=manifest META-INF/signature002.p7s plano.pdf",
				"META-INF/ASiCManifest001.xml=manifest META-INF/signature001.p7s plano.pdf memoria.txt",
				"META-INF/signature001.p7s=first+countersigned", "META-INF/signature002.p7s=second+countersigned"}, domain.Cades,
			[]string{"manifest META-INF/signature001.p7s plano.pdf memoria.txt", "manifest META-INF/signature002.p7s plano.pdf"}},
		// A container of both kinds is reported by the kind found first.
		"ASiC-E of both kinds": {domain.ASiCE, []application.ContainerEntry{{Name: "META-INF/signatures001.xml", Content: []byte("xml")},
			{Name: "META-INF/ASiCManifest002.xml", Content: []byte("manifest META-INF/signature002.p7s plano.pdf")},
			{Name: "META-INF/signature002.p7s", Content: []byte("p7s")}},
			[]string{"META-INF/signatures001.xml=xml+countersigned", "META-INF/ASiCManifest002.xml=manifest META-INF/signature002.p7s plano.pdf",
				"META-INF/signature002.p7s=p7s+countersigned"}, domain.Xades, []string{"manifest META-INF/signature002.p7s plano.pdf"}},
	} {
		store := newFakeStore(map[string][]byte{"/tmp/expediente.asice": []byte("zip")})
		cades, xades := &countingCades{}, &countingXades{}
		containers := &fakeContainers{held: check.container, heldEntries: append(append([]application.ContainerEntry{}, documents...), check.signatures...)}
		useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), cades, &fakePades{}, xades).
			WithContainers(containers)
		artefact, err := useCase.Execute(context.Background(), application.Request{Document: newDocument(t, "/tmp/expediente.asice"),
			Format: domain.Cades, Level: domain.BES, Signer: newSigner(t), Countersign: "all", Location: "Sevilla"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got []string
		for _, entry := range containers.entries {
			if strings.HasPrefix(entry.Name, "META-INF/") {
				got = append(got, entry.Name+"="+string(entry.Content))
			} else if string(entry.Content) != map[string]string{"plano.pdf": "%PDF", "memoria.txt": "m"}[entry.Name] {
				t.Errorf("%s: the document %s changed", name, entry.Name)
			}
		}
		if strings.Join(got, "|") != strings.Join(check.want, "|") || containers.container != check.container ||
			artefact.Path != "/tmp/expediente_countersigned.asice" || artefact.Format != check.format {
			t.Errorf("%s: %q into %s at %s as %s", name, got, containers.container, artefact.Path, artefact.Format)
		}
		var signs []string
		for _, request := range cades.requests {
			signs = append(signs, string(request.DetachedContent))
			if request.Countersign != "all" || request.Cosign {
				t.Errorf("%s: %+v", name, request)
			}
		}
		if strings.Join(signs, "|") != strings.Join(check.signs, "|") {
			t.Errorf("%s: the CAdES files sign %q", name, signs)
		}
		for _, request := range xades.requests {
			if request.Countersign != "all" || request.Packaging != domain.XMLEnveloped || request.Place.City != "Sevilla" {
				t.Errorf("%s: %+v", name, request)
			}
		}
	}
}

// TestACounterSignatureWithNothingToSignWritesNothing: a container without
// signatures, or one whose signature fails, is left as it was.
func TestACounterSignatureWithNothingToSignWritesNothing(t *testing.T) {
	plain := []application.ContainerEntry{{Name: "plano.pdf", Content: []byte("%PDF")}, {Name: "META-INF/manifest.xml", Content: []byte("x")}}
	signed := []application.ContainerEntry{{Name: "plano.pdf", Content: []byte("%PDF")}, {Name: "META-INF/signature.p7s", Content: []byte("p7s")}}
	for name, check := range map[string]struct {
		entries []application.ContainerEntry
		cades   *countingCades
		want    string
	}{
		"no signature":     {plain, &countingCades{}, "no CAdES or XAdES signature"},
		"a failed signing": {signed, &countingCades{failWith: errors.New("the card is gone")}, "META-INF/signature.p7s: the card is gone"},
	} {
		store := newFakeStore(map[string][]byte{"/tmp/plano.pdf.asics": []byte("zip")})
		containers := &fakeContainers{held: domain.ASiCS, heldEntries: check.entries}
		useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)}, selfSignedIdentity(), check.cades, &fakePades{}, &countingXades{}).
			WithContainers(containers)
		_, err := useCase.Execute(context.Background(), application.Request{Document: newDocument(t, "/tmp/plano.pdf.asics"),
			Format: domain.Cades, Level: domain.BES, Signer: newSigner(t), Countersign: "leaves"})
		if err == nil || !strings.Contains(err.Error(), check.want) || containers.entries != nil || len(store.written) != 0 {
			t.Errorf("%s: %v, wrote %v", name, err, store.written)
		}
	}
}
