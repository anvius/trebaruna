package application_test

import (
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/verification/application"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// layeredOpener treats "env(x)" as an envelope around x.
type layeredOpener struct{}

func (layeredOpener) Open(envelope []byte) ([]byte, error) {
	text := string(envelope)
	if len(text) < 5 || text[:4] != "env(" {
		return nil, errors.New("not an envelope")
	}
	return []byte(text[4 : len(text)-1]), nil
}

func (o layeredOpener) IsEnvelope(data []byte) bool {
	_, err := o.Open(data)
	return err == nil
}

type memoryFiles struct{ files map[string][]byte }

func (m *memoryFiles) Read(path string) ([]byte, error) {
	if content, ok := m.files[path]; ok {
		return content, nil
	}
	return nil, errors.New("no such file")
}
func (m *memoryFiles) Exists(path string) bool { _, ok := m.files[path]; return ok }
func (m *memoryFiles) Write(path string, content []byte) error {
	m.files[path] = content
	return nil
}

func TestEveryEnvelopeIsOpened(t *testing.T) {
	files := &memoryFiles{files: map[string][]byte{"/d/atto.pdf.p7m.p7m": []byte("env(env(%PDF))")}}
	result, err := application.NewExtractDocument(files, layeredOpener{}).Execute(application.ExtractRequest{Envelope: "/d/atto.pdf.p7m.p7m"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Path != "/d/atto.pdf" || result.Layers != 2 || string(files.files["/d/atto.pdf"]) != "%PDF" {
		t.Errorf("result = %+v, written %q", result, files.files["/d/atto.pdf"])
	}
}

func TestAnExistingFileIsNeverOverwritten(t *testing.T) {
	files := &memoryFiles{files: map[string][]byte{"/d/a.pdf.p7m": []byte("env(new)"), "/d/a.pdf": []byte("old")}}
	_, err := application.NewExtractDocument(files, layeredOpener{}).Execute(application.ExtractRequest{Envelope: "/d/a.pdf.p7m"})
	if !errors.Is(err, application.ErrWouldOverwrite) || string(files.files["/d/a.pdf"]) != "old" {
		t.Fatalf("err = %v, file = %q", err, files.files["/d/a.pdf"])
	}
}

func TestSomethingThatIsNotAnEnvelopeIsRefused(t *testing.T) {
	files := &memoryFiles{files: map[string][]byte{"/d/a.p7m": []byte("plain")}}
	if _, err := application.NewExtractDocument(files, layeredOpener{}).Execute(application.ExtractRequest{Envelope: "/d/a.p7m"}); err == nil {
		t.Fatal("a file that is not an envelope must be refused")
	}
}

func TestAnUnreadableEnvelopeIsReported(t *testing.T) {
	files := &memoryFiles{files: map[string][]byte{}}
	if _, err := application.NewExtractDocument(files, layeredOpener{}).Execute(application.ExtractRequest{Envelope: "/missing.p7m"}); err == nil {
		t.Fatal("a missing envelope must be reported")
	}
}

func TestTheExtractedNameDropsTheEnvelopeSuffixes(t *testing.T) {
	cases := map[string]string{
		"/d/contratto.pdf.p7m":     "/d/contratto.pdf",
		"/d/contratto.pdf.P7M.p7m": "/d/contratto.pdf",
		"/d/firma.xml.p7s":         "/d/firma.xml",
		"/d/strano.bin":            "/d/strano.bin.extracted",
	}
	for envelope, want := range cases {
		if got := domain.ExtractedName(envelope); got != want {
			t.Errorf("ExtractedName(%q) = %q, want %q", envelope, got, want)
		}
	}
}
