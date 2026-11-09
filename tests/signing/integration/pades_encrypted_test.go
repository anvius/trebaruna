package integration_test

// Signing encrypted PDFs (ISO 32000-1, 7.6): qpdf makes them, with AES-256,
// AES-128 and RC4; trebaruna signs with the user password, invisibly and
// with a seal; pdfsig verifies each with the password and qpdf finds the
// file sound. Permissions that forbid signing are honoured.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func encryptedPDF(t *testing.T, directory, name string, arguments ...string) []byte {
	t.Helper()
	plain := filepath.Join(directory, "plain.pdf")
	if _, err := os.Stat(plain); err != nil {
		if err := os.WriteFile(plain, blankPDFBytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(directory, name)
	command := append(append([]string{"--allow-weak-crypto", "--encrypt"}, arguments...), "--", plain, output)
	if out, err := exec.Command("qpdf", command...).CombinedOutput(); err != nil {
		t.Fatalf("qpdf %v: %v\n%s", command, err, out)
	}
	content, _ := os.ReadFile(output)
	return content
}

func TestAnEncryptedPDFIsSignedWithItsPassword(t *testing.T) {
	for _, tool := range []string{"qpdf", "pdfsig"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not available")
		}
	}
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	directory := t.TempDir()
	for name, arguments := range map[string][]string{
		"AES-256": {"abierto", "propietario", "256"},
		"AES-128": {"abierto", "propietario", "128", "--use-aes=y"},
		"RC4-128": {"abierto", "propietario", "128", "--use-aes=n"},
	} {
		content := encryptedPDF(t, directory, strings.ReplaceAll(name, "-", "")+".pdf", arguments...)
		for _, visible := range []bool{false, true} {
			request := application.PadesRequest{Content: content, Signer: signer, Level: domain.BES, Password: "abierto", Invisible: !visible}
			if visible {
				placement, _ := domain.PlaceSeal(1, 300, 60, 520, 120)
				request.Placements = []domain.SealPlacement{placement}
			}
			signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), request)
			if err != nil {
				t.Fatalf("%s, visible %t: %v", name, visible, err)
			}
			path := filepath.Join(directory, "signed.pdf")
			os.WriteFile(path, signed, 0o600)
			if output, _ := exec.Command("pdfsig", "-upw", "abierto", path).CombinedOutput(); !strings.Contains(string(output), "Signature is Valid") {
				t.Errorf("%s, visible %t: pdfsig says\n%s", name, visible, output)
			}
			if output, err := exec.Command("qpdf", "--password=abierto", "--check", path).CombinedOutput(); err != nil {
				t.Errorf("%s, visible %t: qpdf --check: %v\n%s", name, visible, err, output)
			}
			checkContentsGap(t, name, signed)
			decrypted := filepath.Join(directory, "decrypted.pdf")
			if output, err := exec.Command("qpdf", "--password=abierto", "--decrypt", "--qdf", "--object-streams=disable", path, decrypted).CombinedOutput(); err != nil {
				t.Fatalf("qpdf --decrypt: %v\n%s", err, output)
			}
			if plain, _ := os.ReadFile(decrypted); !regexp.MustCompile(`/Name \(Test Signer\)`).Match(plain) {
				t.Errorf("%s, visible %t: the signature's strings do not decrypt to its signer", name, visible)
			}
			verifier := verificationinfra.NewPDFVerifier()
			if _, err := verifier.Extract(path); err == nil {
				t.Errorf("%s: verified without its password", name)
			}
			verifier.Password = "abierto"
			if reports, err := verifier.Extract(path); err != nil || len(reports) != 1 {
				t.Errorf("%s, visible %t: trebaruna verifies it with the password: %v", name, visible, err)
			}
		}
	}
}

func TestAnEncryptedPDFIsRefusedWhenItSaysSo(t *testing.T) {
	if _, err := exec.LookPath("qpdf"); err != nil {
		t.Skip("qpdf is not available")
	}
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	directory := t.TempDir()
	locked := encryptedPDF(t, directory, "locked.pdf", "abierto", "propietario", "256")
	restricted := encryptedPDF(t, directory, "restricted.pdf", "", "propietario", "256", "--form=n", "--annotate=n", "--modify=none")
	permissive := encryptedPDF(t, directory, "permissive.pdf", "", "propietario", "256")
	for name, test := range map[string]struct {
		request application.PadesRequest
		reason  string
	}{
		"no password":    {application.PadesRequest{Content: locked}, "TREBARUNA_PDF_PASSWORD"},
		"wrong password": {application.PadesRequest{Content: locked, Password: "mal"}, "does not open it"},
		"no signing":     {application.PadesRequest{Content: restricted}, "permissions"},
		"LT":             {application.PadesRequest{Content: locked, Password: "abierto", Level: domain.LT, EmbedRevocation: true, TimestampURL: "http://tsa.invalid"}, "level lt"},
	} {
		test.request.Signer = signer
		if test.request.Level == "" {
			test.request.Level = domain.BES
		}
		_, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), test.request)
		if !errors.Is(err, infrastructure.ErrEncryptedPDF) || !strings.Contains(err.Error(), test.reason) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(),
		application.PadesRequest{Content: permissive, Signer: signer, Level: domain.BES, Invisible: true}); err != nil {
		t.Errorf("a document that only restricts nothing it needs signs without a password: %v", err)
	}
}

// checkContentsGap: the bytes /ByteRange leaves out are exactly the
// signature's /Contents string, brackets included, as ISO 32000-1 12.8.1
// asks; an encrypted /Contents would outgrow its gap.
func checkContentsGap(t *testing.T, name string, signed []byte) {
	t.Helper()
	match := regexp.MustCompile(`/ByteRange \[\s*0\s+(\d+)\s+(\d+)\s+\d+\s*\]`).FindAllSubmatch(signed, -1)
	if len(match) == 0 {
		t.Fatalf("%s: no /ByteRange", name)
	}
	last := match[len(match)-1]
	start, _ := strconv.Atoi(string(last[1]))
	end, _ := strconv.Atoi(string(last[2]))
	if signed[start] != '<' || signed[end-1] != '>' || bytes.IndexByte(signed[start:end], '>') != end-start-1 {
		t.Errorf("%s: the gap of /ByteRange is not the /Contents string", name)
	}
}
