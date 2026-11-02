package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	"codeberg.org/simplicer/firma-it/src/signing/domain"
)

// fakeStore is an in-memory FileStore.
type fakeStore struct {
	files   map[string][]byte
	written map[string][]byte
	readErr error
}

func newFakeStore(files map[string][]byte) *fakeStore {
	return &fakeStore{files: files, written: map[string][]byte{}}
}

func (f *fakeStore) Read(path string) ([]byte, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	content, ok := f.files[path]
	if !ok {
		return nil, errors.New("not found")
	}
	return content, nil
}

func (f *fakeStore) Write(path string, content []byte) error {
	f.written[path] = content
	return nil
}

// fakeClock freezes time.
type fakeClock struct{ moment time.Time }

func (f fakeClock) Now() time.Time { return f.moment }

// fakeCades records the request and returns a marker.
type fakeCades struct {
	called  bool
	request application.CadesRequest
}

func (f *fakeCades) SignCades(_ context.Context, request application.CadesRequest) ([]byte, error) {
	f.called = true
	f.request = request
	return []byte("cades-output"), nil
}

// fakePades records the request.
type fakePades struct {
	called  bool
	request application.PadesRequest
}

func (f *fakePades) SignPades(_ context.Context, request application.PadesRequest) ([]byte, error) {
	f.called = true
	f.request = request
	return []byte("pades-output"), nil
}

// fakeXades records the request.
type fakeXades struct {
	called  bool
	request application.XadesRequest
}

func (f *fakeXades) SignXades(_ context.Context, request application.XadesRequest) ([]byte, error) {
	f.called = true
	f.request = request
	return []byte("xades-output"), nil
}

func newSigner(t *testing.T) domain.Signer {
	t.Helper()
	signer, err := domain.NewSigner("Mario Rossi", domain.FromP12,
		domain.WithKeyMaterial([]byte("p12")))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	return signer
}

func newDocument(t *testing.T, path string) domain.Document {
	t.Helper()
	document, err := domain.OpenDocument(path)
	if err != nil {
		t.Fatalf("build document: %v", err)
	}
	return document
}

// fakeIdentity reports a fixed identity.
type fakeIdentity struct{ identity application.Identity }

func (f fakeIdentity) Resolve(domain.Signer) (application.Identity, error) {
	return f.identity, nil
}

// selfSignedIdentity is the identity used across these tests.
func selfSignedIdentity() fakeIdentity {
	return fakeIdentity{identity: application.Identity{
		Subject:    "CN=Mario Rossi",
		Issuer:     "CN=Mario Rossi",
		SelfSigned: true,
		KeySource:  domain.FromP12,
	}}
}

func TestSignDocumentWritesArtefactWithDerivedName(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/contratto.xml": []byte("content")})
	cades := &fakeCades{}
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		selfSignedIdentity(), cades, &fakePades{}, &fakeXades{})

	artefact, err := useCase.Execute(context.Background(), application.Request{
		Document: newDocument(t, "/tmp/contratto.xml"),
		Format:   domain.Cades,
		Level:    domain.BES,
		Signer:   newSigner(t),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if !cades.called {
		t.Fatal("CAdES adapter was not called")
	}
	if artefact.Path != "/tmp/contratto.xml.p7m" {
		t.Errorf("path = %q, want the CAdES convention", artefact.Path)
	}
	if string(store.written["/tmp/contratto.xml.p7m"]) != "cades-output" {
		t.Error("artefact was not written to the store")
	}
	if artefact.Size != len("cades-output") {
		t.Errorf("size = %d", artefact.Size)
	}
	if artefact.Format.Standard() != "ETSI EN 319 122-1" {
		t.Errorf("standard = %q", artefact.Format.Standard())
	}
}

func TestSignDocumentRespectsExplicitOutput(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/a.pdf": []byte("pdf")})
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		selfSignedIdentity(), &fakeCades{}, &fakePades{}, &fakeXades{})

	artefact, err := useCase.Execute(context.Background(), application.Request{
		Document:   newDocument(t, "/tmp/a.pdf"),
		Format:     domain.Pades,
		Level:      domain.BES,
		Signer:     newSigner(t),
		OutputPath: "/tmp/custom.pdf",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if artefact.Path != "/tmp/custom.pdf" {
		t.Errorf("path = %q, want the explicit output", artefact.Path)
	}
}

func TestSignDocumentRejectsFormatUnsupportedByDocument(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/a.pdf": []byte("pdf")})
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		selfSignedIdentity(), &fakeCades{}, &fakePades{}, &fakeXades{})

	_, err := useCase.Execute(context.Background(), application.Request{
		Document: newDocument(t, "/tmp/a.pdf"),
		Format:   domain.Xades,
		Level:    domain.BES,
		Signer:   newSigner(t),
	})
	if !errors.Is(err, domain.ErrUnsupportedFormat) {
		t.Fatalf("err = %v, want ErrUnsupportedFormat", err)
	}
}

func TestSignDocumentRejectsLevelWithoutTimestampAuthority(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/a.xml": []byte("xml")})
	pades := &fakePades{}
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		selfSignedIdentity(), &fakeCades{}, pades, &fakeXades{})

	_, err := useCase.Execute(context.Background(), application.Request{
		Document: newDocument(t, "/tmp/a.xml"),
		Format:   domain.Cades,
		Level:    domain.T,
		Signer:   newSigner(t),
	})
	if err == nil {
		t.Fatal("level T without --tsa must fail")
	}
	if pades.called {
		t.Error("no adapter should run when validation fails")
	}
}

func TestSignDocumentPassesSealToPadesAdapter(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/a.pdf": []byte("pdf")})
	pades := &fakePades{}
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		selfSignedIdentity(), &fakeCades{}, pades, &fakeXades{})

	placement, _ := domain.PlaceSeal(3, 100, 600, 300, 700)
	artefact, err := useCase.Execute(context.Background(), application.Request{
		Document:  newDocument(t, "/tmp/a.pdf"),
		Format:    domain.Pades,
		Level:     domain.BES,
		Signer:    newSigner(t),
		Placement: placement,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !artefact.HasSeal {
		t.Error("artefact should report a seal")
	}
	if pades.request.Placement.Page() != 3 {
		t.Errorf("seal page = %d, want 3", pades.request.Placement.Page())
	}
}

func TestSignDocumentPropagatesReadErrors(t *testing.T) {
	store := newFakeStore(map[string][]byte{})
	store.readErr = errors.New("permission denied")
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		selfSignedIdentity(), &fakeCades{}, &fakePades{}, &fakeXades{})

	_, err := useCase.Execute(context.Background(), application.Request{
		Document: newDocument(t, "/tmp/missing.xml"),
		Format:   domain.Cades,
		Level:    domain.BES,
		Signer:   newSigner(t),
	})
	if err == nil {
		t.Fatal("a read error must abort the use case")
	}
}

func TestSignDocumentRejectsMissingAdapter(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/a.pdf": []byte("pdf")})
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		selfSignedIdentity(), nil, nil, nil)

	_, err := useCase.Execute(context.Background(), application.Request{
		Document: newDocument(t, "/tmp/a.pdf"),
		Format:   domain.Pades,
		Level:    domain.BES,
		Signer:   newSigner(t),
	})
	if err == nil {
		t.Fatal("a missing adapter must be reported")
	}
}

func TestSignDocumentReportsSignerName(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/a.xml": []byte("xml")})
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		selfSignedIdentity(), &fakeCades{}, &fakePades{}, &fakeXades{})

	artefact, err := useCase.Execute(context.Background(), application.Request{
		Document: newDocument(t, "/tmp/a.xml"),
		Format:   domain.Cades,
		Level:    domain.BES,
		Signer:   newSigner(t),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if artefact.SignerName != "Mario Rossi" {
		t.Errorf("signer = %q", artefact.SignerName)
	}
}

func TestSealOnlyReportedForPades(t *testing.T) {
	store := newFakeStore(map[string][]byte{
		"/tmp/a.pdf": []byte("pdf"),
		"/tmp/a.xml": []byte("xml"),
	})
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		selfSignedIdentity(), &fakeCades{}, &fakePades{}, &fakeXades{})

	placement, _ := domain.PlaceSeal(1, 10, 10, 210, 80)

	pdfArtefact, err := useCase.Execute(context.Background(), application.Request{
		Document:  newDocument(t, "/tmp/a.pdf"),
		Format:    domain.Pades,
		Level:     domain.BES,
		Signer:    newSigner(t),
		Placement: placement,
	})
	if err != nil {
		t.Fatalf("PAdES: %v", err)
	}
	if !pdfArtefact.HasSeal {
		t.Error("PAdES with a placement must report a seal")
	}

	// The same placement on CAdES is meaningless: a .p7m has no page.
	cadesArtefact, err := useCase.Execute(context.Background(), application.Request{
		Document:  newDocument(t, "/tmp/a.xml"),
		Format:    domain.Cades,
		Level:     domain.BES,
		Signer:    newSigner(t),
		Placement: placement,
	})
	if err != nil {
		t.Fatalf("CAdES: %v", err)
	}
	if cadesArtefact.HasSeal {
		t.Error("CAdES must never report a visible seal")
	}
}

func TestSelfSignedIsReported(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/a.xml": []byte("xml")})
	resolver := fakeIdentity{identity: application.Identity{
		Subject: "CN=Autofirmado", Issuer: "CN=Autofirmado", SelfSigned: true,
	}}
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		resolver, &fakeCades{}, &fakePades{}, &fakeXades{})

	artefact, err := useCase.Execute(context.Background(), application.Request{
		Document: newDocument(t, "/tmp/a.xml"),
		Format:   domain.Cades,
		Level:    domain.BES,
		Signer:   newSigner(t),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !artefact.SelfSigned {
		t.Error("a self-signed certificate must be reported, never hidden")
	}
}

func TestTrustedCertificateIsNotFlagged(t *testing.T) {
	store := newFakeStore(map[string][]byte{"/tmp/a.xml": []byte("xml")})
	resolver := fakeIdentity{identity: application.Identity{
		Subject: "CN=Mario Rossi", Issuer: "CN=ArubaPEC CA", SelfSigned: false,
	}}
	useCase := application.NewSignDocument(store, fakeClock{time.Unix(0, 0)},
		resolver, &fakeCades{}, &fakePades{}, &fakeXades{})

	artefact, err := useCase.Execute(context.Background(), application.Request{
		Document: newDocument(t, "/tmp/a.xml"),
		Format:   domain.Cades,
		Level:    domain.BES,
		Signer:   newSigner(t),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if artefact.SelfSigned {
		t.Error("a CA-issued certificate must not be flagged as self-signed")
	}
}
