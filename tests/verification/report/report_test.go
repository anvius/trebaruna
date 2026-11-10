package report_test

// The report says the same in Markdown, HTML and PDF, escapes what the
// verification carries (names come from certificates anyone can make), and
// the PDF is judged by poppler and qpdf.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"codeberg.org/simplicer/trebaruna/src/verification/infrastructure/report"
	"codeberg.org/simplicer/trebaruna/src/verification/messaging"
)

func input(findings int) report.Input {
	home, _ := os.UserHomeDir()
	signer := domain.SignerReport{
		FieldName:  "Signature1",
		SignerName: `Ñandú <script>alert(1)</script> | Pérez (notario)`,
		Issuer:     "Autoridad de Certificación «Prueba»",
		Format:     "PAdES",
		SignedAt:   time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC),
		NotBefore:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:   time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
		Integrity:  domain.StatusGood,
		Trust:      domain.TrustAdvanced,
		Findings: []domain.Finding{
			{Code: "signature.intact", Status: domain.StatusGood, Message: "the signed content is unaltered"},
			{Code: "trustlist.unavailable", Status: domain.StatusWarn, Message: "no list", Detail: filepath.Join(home, ".cache", "trebaruna", "EU.xml")},
		},
	}
	for index := 0; index < findings; index++ {
		signer.Findings = append(signer.Findings, domain.Finding{Code: "verification.warning", Status: domain.StatusWarn,
			Message: "a finding", Detail: fmt.Sprintf("detalle número %d con acentos: á é í ó ú ñ €", index)})
	}
	return report.Input{
		Report: domain.DocumentReport{
			Path: "contrato de arrendamiento.pdf", Format: "pdf", Signed: true, Signers: []domain.SignerReport{signer},
			VerifiedAt: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC),
		},
		Catalogue: messaging.Spanish, Language: "es", Digest: strings.Repeat("ab", 32), Tool: "trebaruna 0.36.0-unstable",
		Network: []transparency.Connection{{Purpose: "revocation", Method: "POST", URL: "http://ocsp.example/", Status: 200}},
	}
}

func render(t *testing.T, format report.Format, in report.Input) []byte {
	t.Helper()
	out, err := report.Render(format, in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTheThreeFormatsSayTheSame: verdict, signer, findings, connections.
func TestTheThreeFormatsSayTheSame(t *testing.T) {
	markdown := string(render(t, report.Markdown, input(0)))
	html := string(render(t, report.HTML, input(0)))
	for _, expected := range []string{"Informe de verificación", "avanzada", "Pérez", "el contenido firmado no se ha modificado",
		"http://ocsp.example/", strings.Repeat("ab", 32)} {
		if !strings.Contains(markdown, expected) || !strings.Contains(html, expected) {
			t.Errorf("%q missing from Markdown or HTML", expected)
		}
	}
	if strings.Contains(markdown+html, "/home/") || !strings.Contains(markdown, "~/.cache") {
		t.Error("the home directory must read as ~")
	}
}

// TestWhatACertificateSaysIsEscaped: a certificate name is data, never markup.
func TestWhatACertificateSaysIsEscaped(t *testing.T) {
	html := render(t, report.HTML, input(0))
	if bytes.Contains(html, []byte("<script>")) {
		t.Error("a certificate name must not become HTML")
	}
	decoder := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(html, []byte("<!DOCTYPE html>\n"))))
	for {
		if _, err := decoder.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("the HTML is not well formed: %v", err)
		}
	}
	if !bytes.Contains(html, []byte(`<html lang="es">`)) {
		t.Error("the page declares its language")
	}
	markdown := string(render(t, report.Markdown, input(0)))
	if !strings.Contains(markdown, `\| Pérez`) || strings.Contains(markdown, "<script>") {
		t.Errorf("Markdown cell: %s", markdown)
	}
}

// TestThePDFReadsBackInPoppler, accents and parentheses included, over
// several pages with their footer.
func TestThePDFReadsBackInPoppler(t *testing.T) {
	pdf := render(t, report.PDF, input(120))
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) || !bytes.HasSuffix(pdf, []byte("%%EOF\n")) {
		t.Fatal("not a PDF")
	}
	path := filepath.Join(t.TempDir(), "informe.pdf")
	if err := os.WriteFile(path, pdf, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("qpdf"); err == nil {
		if output, err := exec.Command("qpdf", "--check", path).CombinedOutput(); err != nil {
			t.Errorf("qpdf: %v\n%s", err, output)
		}
	}
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("poppler is not installed")
	}
	text, err := exec.Command("pdftotext", "-layout", path, "-").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Informe de verificación", "Certificado válido", "Pérez (notario)", "detalle número 119 con acentos: á é í ó ú ñ €",
		"Informe de verificación — 1/"} {
		if !strings.Contains(string(text), expected) {
			t.Errorf("pdftotext lacks %q", expected)
		}
	}
	if pages := bytes.Count(pdf, []byte("/Type /Page ")); pages < 2 {
		t.Errorf("%d page(s) for 120 findings", pages)
	}
}

// TestTheFormatComesFromTheName.
func TestTheFormatComesFromTheName(t *testing.T) {
	for name, want := range map[string]report.Format{"a.md": report.Markdown, "a.HTML": report.HTML, "a.pdf": report.PDF} {
		if got, err := report.FormatFor(name); err != nil || got != want {
			t.Errorf("%s: %s %v", name, got, err)
		}
	}
	if _, err := report.FormatFor("a.docx"); err == nil {
		t.Error("a Word file is not a report format")
	}
}

// TestCentralEuropeanLettersPrintInThePDFReport: a Polish report for a
// signer whose name needs letters WinAnsi lacks (Polish, Czech, Hungarian)
// prints whole, its labels and its title too: poppler reads them back
// through the glyph names the fonts' encoding gives, and qpdf accepts the
// file.
func TestCentralEuropeanLettersPrintInThePDFReport(t *testing.T) {
	in := input(3)
	in.Catalogue, in.Language = messaging.Polish, "pl"
	in.Report.Signers[0].SignerName = "Łukasz Żółć, Jiří Dvořák, Árpád Kővári"
	pdf := render(t, report.PDF, in)
	if !bytes.Contains(pdf, []byte("/Differences [")) || !bytes.Contains(pdf, []byte("/lslash")) {
		t.Error("the fonts' encoding names no extra glyph")
	}
	path := filepath.Join(t.TempDir(), "raport.pdf")
	if err := os.WriteFile(path, pdf, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("qpdf"); err == nil {
		if output, err := exec.Command("qpdf", "--check", path).CombinedOutput(); err != nil {
			t.Errorf("qpdf: %v\n%s", err, output)
		}
	}
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("poppler is not installed")
	}
	text, err := exec.Command("pdftotext", "-layout", path, "-").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Łukasz Żółć", "Jiří Dvořák", "Árpád Kővári", messaging.Polish.LabelConnections} {
		if !strings.Contains(string(text), expected) {
			t.Errorf("pdftotext lacks %q in:\n%s", expected, text)
		}
	}
	information, err := exec.Command("pdfinfo", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(information), messaging.Polish.ReportTitle) {
		t.Errorf("the document title is not %q:\n%s", messaging.Polish.ReportTitle, information)
	}
}
