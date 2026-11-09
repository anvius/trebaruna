package asic_test

// ASiC time-stamp tokens (ETSI EN 319 162-1, 4.3 and 4.4): an ASiC-S with
// META-INF/timestamp.tst over its document, as `trebaruna timestamp
// --asic` writes it, and an ASiC-E whose timestamp covers an ASiCManifest.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/asic"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"codeberg.org/simplicer/trebaruna/tests/support/tsa"
)

func tokenOver(t *testing.T, authority *tsa.Authority, content []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(content)
	response, err := authority.Token(context.Background(), digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := cms.ExtractToken(response)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func writeContainer(t *testing.T, name, mediaType string, entries []asic.Entry) string {
	t.Helper()
	container, err := asic.Write(mediaType, entries)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, container, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestATimestampedContainerIsVerified(t *testing.T) {
	authority := tsa.New(t)
	document := []byte("%PDF-1.7 solicitud")
	token := tokenOver(t, authority, document)
	for name, check := range map[string]struct {
		document []byte
		want     domain.Status
	}{
		"the document timestamped": {document, domain.StatusGood},
		"another document":         {[]byte("%PDF-1.7 solicitud cambiada"), domain.StatusBad},
	} {
		path := writeContainer(t, "solicitud.pdf.asics", signingdomain.ASiCS.MediaType(), []asic.Entry{
			{Name: "solicitud.pdf", Content: check.document}, {Name: "META-INF/timestamp.tst", Content: token}})
		roots := x509.NewCertPool()
		roots.AddCert(authority.CA)
		reports, err := verifier().WithAnchorCertificates(roots, nil, []*x509.Certificate{authority.CA}).Extract(path)
		if err != nil || len(reports) != 1 {
			t.Fatalf("%s: %v %v", name, reports, err)
		}
		report := reports[0]
		covers, _ := finding(report, "container.covers")
		_, trusted := finding(report, "certificate.trusted")
		if report.Integrity != check.want || report.Format != "RFC 3161" || !report.Timestamped || report.SignedAt.IsZero() ||
			report.FieldName != "META-INF/timestamp.tst" || covers.Detail != "solicitud.pdf" || !trusted {
			t.Errorf("%s: %+v", name, report)
		}
	}

	// openssl reads META-INF/timestamp.tst as a token over the document.
	if _, err := exec.LookPath("openssl"); err == nil {
		directory := t.TempDir()
		files := map[string][]byte{"document": document, "timestamp.tst": token,
			"ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.CA.Raw})}
		for name, content := range files {
			os.WriteFile(filepath.Join(directory, name), content, 0o600)
		}
		output, err := exec.Command("openssl", "ts", "-verify", "-token_in", "-in", filepath.Join(directory, "timestamp.tst"),
			"-data", filepath.Join(directory, "document"), "-CAfile", filepath.Join(directory, "ca.pem")).CombinedOutput()
		if err != nil {
			t.Errorf("openssl ts -verify: %v\n%s", err, output)
		}
	}

	path := writeContainer(t, "solicitud.pdf.asics", signingdomain.ASiCS.MediaType(), []asic.Entry{
		{Name: "solicitud.pdf", Content: document}, {Name: "META-INF/timestamp.tst", Content: token}})
	reports, err := verifier().Extract(path)
	if _, untrusted := finding(reports[0], "certificate.untrusted_issuer"); err != nil || !untrusted {
		t.Errorf("an authority no list vouches for: %+v %v", reports, err)
	}
}

func TestAnExtendedContainersTimestampCoversItsManifest(t *testing.T) {
	authority := tsa.New(t)
	documents := []asic.Entry{{Name: "plano.pdf", Content: []byte("%PDF plano")}, {Name: "memoria.txt", Content: []byte("memoria")}}
	manifest, err := asic.Manifest("META-INF/timestamp001.tst", documents)
	if err != nil {
		t.Fatal(err)
	}
	entries := append(append([]asic.Entry{}, documents...),
		asic.Entry{Name: "META-INF/ASiCManifest001.xml", Content: manifest},
		asic.Entry{Name: "META-INF/timestamp001.tst", Content: tokenOver(t, authority, manifest)})
	path := writeContainer(t, "expediente.asice", signingdomain.ASiCE.MediaType(), entries)
	reports, err := verifier().Extract(path)
	if err != nil || len(reports) != 1 || reports[0].Integrity != domain.StatusGood {
		t.Fatalf("%+v %v", reports, err)
	}
	if covers, _ := finding(reports[0], "container.covers"); covers.Detail != "plano.pdf, memoria.txt" {
		t.Errorf("covers %q", covers.Detail)
	}

	entries[0].Content = []byte("%PDF otro plano")
	reports, err = verifier().Extract(writeContainer(t, "expediente.asice", signingdomain.ASiCE.MediaType(), entries))
	if err != nil || reports[0].Integrity != domain.StatusBad {
		t.Errorf("a file the manifest lists, changed: %+v %v", reports, err)
	}
}
