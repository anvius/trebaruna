package integration_test

// A PDF/A document stays PDF/A when it is signed with a seal: Ghostscript
// makes PDF/A-1b and PDF/A-2b files; the seal's fonts are embedded
// (pdffonts), a PDF/A-1 rubric carries no soft mask (qpdf), the signature
// verifies (pdfsig), and veraPDF passes the file when it is installed
// (VERAPDF names it, or it is on the PATH).

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// pdfaDocument converts a plain PDF to PDF/A with Ghostscript's definition
// file, pointed at an sRGB profile.
func pdfaDocument(t *testing.T, directory string, part int) []byte {
	t.Helper()
	definition, _ := filepath.Glob("/usr/share/ghostscript/*/lib/PDFA_def.ps")
	profiles, _ := filepath.Glob("/usr/share/color/icc/sRGB*.icc")
	if _, err := exec.LookPath("gs"); err != nil || len(definition) == 0 || len(profiles) == 0 {
		t.Skip("Ghostscript with PDFA_def.ps and an sRGB profile is not available")
	}
	profile, _ := os.ReadFile(profiles[0])
	os.WriteFile(filepath.Join(directory, "srgb.icc"), profile, 0o600)
	template, _ := os.ReadFile(definition[0])
	lines := strings.Split(string(template), "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, "/ICCProfile (") {
			lines[index] = "/ICCProfile (srgb.icc) % Customise"
		}
	}
	os.WriteFile(filepath.Join(directory, "PDFA_def.ps"), []byte(strings.Join(lines, "\n")), 0o600)
	os.WriteFile(filepath.Join(directory, "plain.pdf"), blankPDFBytes(), 0o600)
	output := filepath.Join(directory, "pdfa.pdf")
	command := exec.Command("gs", "-q", "-dPDFA="+string(rune('0'+part)), "-dBATCH", "-dNOPAUSE", "-dPDFACompatibilityPolicy=1",
		"-sColorConversionStrategy=RGB", "--permit-file-read=srgb.icc", "-sDEVICE=pdfwrite", "-sOutputFile="+output, "PDFA_def.ps", "plain.pdf")
	command.Dir = directory
	if out, err := command.CombinedOutput(); err != nil || strings.Contains(string(out), "aborted") {
		t.Fatalf("gs: %v\n%s", err, out)
	}
	content, _ := os.ReadFile(output)
	return content
}

// translucentRubric is a stroke on a transparent ground: a soft mask unless
// flattened.
func translucentRubric() []byte {
	picture := image.NewNRGBA(image.Rect(0, 0, 120, 40))
	for x := 10; x < 110; x++ {
		picture.Set(x, 20+(x%7), color.NRGBA{R: 20, G: 30, B: 120, A: 255})
	}
	var out bytes.Buffer
	png.Encode(&out, picture)
	return out.Bytes()
}

func TestAPDFADocumentStaysPDFAWithASeal(t *testing.T) {
	for _, tool := range []string{"pdffonts", "pdfsig", "qpdf"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not available")
		}
	}
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	rubric, err := domain.NewRubric(translucentRubric())
	if err != nil {
		t.Fatal(err)
	}
	verapdf := os.Getenv("VERAPDF")
	if verapdf == "" {
		verapdf, _ = exec.LookPath("verapdf")
	}
	for _, part := range []int{1, 2} {
		directory := t.TempDir()
		content := pdfaDocument(t, directory, part)
		placement, _ := domain.PlaceSeal(1, 300, 60, 560, 140)
		signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{Content: content, Signer: signer,
			Level: domain.BES, Placements: []domain.SealPlacement{placement}, Rubric: rubric})
		if err != nil {
			t.Fatalf("PDF/A-%d: %v", part, err)
		}
		path := filepath.Join(directory, "signed.pdf")
		os.WriteFile(path, signed, 0o600)

		fonts, _ := exec.Command("pdffonts", path).CombinedOutput()
		for _, line := range strings.Split(string(fonts), "\n")[2:] {
			if fields := strings.Fields(line); len(fields) > 3 && !strings.Contains(line, " yes ") {
				t.Errorf("PDF/A-%d: a font is not embedded: %s", part, line)
			}
		}
		if !strings.Contains(string(fonts), "GoRegular") || !strings.Contains(string(fonts), "GoBold") {
			t.Errorf("PDF/A-%d: the seal's fonts are not the embedded ones:\n%s", part, fonts)
		}
		expanded, _ := exec.Command("qpdf", "--qdf", "--object-streams=disable", path, "-").Output()
		if hasMask := bytes.Contains(expanded, []byte("/SMask")); hasMask != (part == 2) {
			t.Errorf("PDF/A-%d: soft mask present %t", part, hasMask)
		}
		if output, _ := exec.Command("pdfsig", path).CombinedOutput(); !strings.Contains(string(output), "Signature is Valid") {
			t.Errorf("PDF/A-%d: pdfsig says\n%s", part, output)
		}
		if verapdf != "" {
			flavour := string(rune('0'+part)) + "b"
			if output, _ := exec.Command(verapdf, "--flavour", flavour, "--format", "text", path).CombinedOutput(); !strings.Contains(string(output), "PASS") {
				t.Errorf("PDF/A-%d: veraPDF says\n%s", part, output)
			}
		}
	}

	// A document that is not PDF/A keeps the light seal: nothing embedded.
	placement, _ := domain.PlaceSeal(1, 300, 60, 520, 120)
	plain, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{Content: blankPDFBytes(), Signer: signer,
		Level: domain.BES, Placements: []domain.SealPlacement{placement}})
	if err != nil || bytes.Contains(plain, []byte("FontFile2")) {
		t.Errorf("a plain PDF's seal embeds fonts: %v", err)
	}
}
