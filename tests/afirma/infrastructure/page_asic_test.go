package infrastructure_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verification "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// TestASiCSPagesGetAContainer: CAdES-ASiC-S and XAdES-ASiC-S answer with
// the container, the data named as AutoFirma names it, and it verifies.
func TestASiCSPagesGetAContainer(t *testing.T) {
	cases := []struct {
		format     string
		properties map[string]string
		data       []byte
		entries    string
	}{
		{"CAdES-ASiC-S", map[string]string{}, []byte("%PDF-1.4\n%solicitud\n"), "mimetype dataobject.pdf META-INF/signature.p7s"},
		{"XAdES-ASiC-S", map[string]string{"asicsFilename": "solicitud.xml"}, []byte("<solicitud/>"), "mimetype solicitud.xml META-INF/signatures.xml"},
		{"XAdES-ASiC-S", map[string]string{}, []byte("texto"), "mimetype dataobject.txt META-INF/signatures.xml"},
	}
	for _, entry := range cases {
		signed, err := signPage(t, entry.format, entry.properties, entry.data)
		if err != nil {
			t.Fatalf("%s: %v", entry.format, err)
		}
		archive, err := zip.NewReader(bytes.NewReader(signed.Signature), int64(len(signed.Signature)))
		if err != nil {
			t.Fatalf("%s: not a ZIP: %v", entry.format, err)
		}
		var names []string
		for _, file := range archive.File {
			names = append(names, file.Name)
		}
		if strings.Join(names, " ") != entry.entries {
			t.Errorf("%s: %v, want %s", entry.format, names, entry.entries)
		}
		path := filepath.Join(t.TempDir(), "firma.asics")
		if err := os.WriteFile(path, signed.Signature, 0o600); err != nil {
			t.Fatal(err)
		}
		reports, err := verification.NewAsicVerifier(verification.NewCadesVerifier(), verification.NewXadesVerifier()).Extract(path)
		if err != nil || len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %+v, %v", entry.format, reports, err)
		}
	}
	_, err := signPage(t, "XAdES-ASiC-S", map[string]string{"asicsFilename": "../evil.xml"}, []byte("<a/>"))
	wantFailure(t, err, domain.Params, "asicsFilename with a path")
}
