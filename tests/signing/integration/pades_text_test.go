package integration_test

// The signature dictionary's /Name, /Reason and /Location are text a
// reader shows: a name with accents must read back as written, not as the
// bytes of its UTF-8 taken for PDFDocEncoding ("José" as "JosÃ©").

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/digitorus/pdf"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

func TestASignaturesTextReadsBackAsWritten(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	command := exec.Command("openssl", "req", "-utf8", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem",
		"-days", "2", "-subj", "/C=ES/CN=José García Núñez")
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v\n%s", err, output)
	}
	key, _ := os.ReadFile(filepath.Join(directory, "k.pem"))
	certificate, _ := os.ReadFile(filepath.Join(directory, "c.pem"))
	// The holder's name comes from the certificate, accents included.
	signer, err := domain.NewSigner(domain.NameFromCertificate, domain.FromPEM, domain.WithKeyMaterial(append(key, certificate...)))
	if err != nil {
		t.Fatal(err)
	}
	placement, _ := domain.PlaceSeal(1, 300, 60, 520, 120)
	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{Content: blankPDFBytes(),
		Signer: signer, Level: domain.BES, Placements: []domain.SealPlacement{placement}, Reason: "Conformidad con el pliego", Location: "Almería"})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := pdf.NewReader(bytes.NewReader(signed), int64(len(signed)))
	if err != nil {
		t.Fatal(err)
	}
	fields := reader.Trailer().Key("Root").Key("AcroForm").Key("Fields")
	signature := fields.Index(fields.Len() - 1).Key("V")
	for key, want := range map[string]string{"Name": "José García Núñez", "Reason": "Conformidad con el pliego", "Location": "Almería"} {
		if got := signature.Key(key).Text(); got != want {
			t.Errorf("/%s reads %q, want %q", key, got, want)
		}
	}
}
