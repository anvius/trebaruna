//go:build gui

package infrastructure

// Screenshots of the real window, rendered by Fyne's software driver.
//
//	TREBARUNA_SCREENSHOTS=/tmp/shots go test -tags gui ./src/desktop/infrastructure -run Screenshots
//
// They are for review, not assertions: a layout defect such as a clipped label
// is obvious in a picture and invisible to a unit test. Without the variable the
// test is skipped, so CI does not need poppler.

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

func TestScreenshots(t *testing.T) {
	directory := os.Getenv("TREBARUNA_SCREENSHOTS")
	if directory == "" {
		t.Skip("set TREBARUNA_SCREENSHOTS to a directory to write screenshots")
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}

	app := test.NewTempApp(t)
	app.Settings().SetTheme(NewAppTheme(DefaultPalette()))
	document := writeSampleContract(t)

	for _, language := range []messaging.Language{messaging.Spanish, messaging.Italian} {
		window := test.NewTempWindow(t, nil)
		desktop := &Window{
			application: application.NewSignFromDesktop(CommandLineSigner{BinaryPath: "trebaruna"}, fileExists),
			preview:     application.NewPreviewPage(NewPopplerRenderer(), application.InkFinder{}),
			window:      window,
			messages:    messaging.For(language),
			palette:     DefaultPalette(),
		}
		window.SetContent(desktop.withTabs(desktop.buildContent(document)))
		window.Resize(fyne.NewSize(1220, 800))

		waitFor(t, func() bool { return desktop.pages.canvas != nil })
		capture(t, window, filepath.Join(directory, fmt.Sprintf("sign-%s.png", language)))
	}
}

// waitFor polls until the preview goroutine has delivered the page.
func waitFor(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		done := false
		fyne.DoAndWait(func() { done = ready() })
		if done {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the page preview never arrived (is poppler installed?)")
}

func capture(t *testing.T, window fyne.Window, path string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := png.Encode(file, window.Canvas().Capture()); err != nil {
		t.Fatal(err)
	}
}

// writeSampleContract writes a two-page PDF with enough text to give the ink
// map something to avoid: a title, paragraphs, and a signature line.
func writeSampleContract(t *testing.T) string {
	t.Helper()
	var page strings.Builder
	page.WriteString("BT /F1 16 Tf 72 770 Td (Contratto di locazione ad uso abitativo) Tj ET\n")
	for line := 0; line < 34; line++ {
		y := 730 - line*16
		fmt.Fprintf(&page, "BT /F1 10 Tf 72 %d Td (Art. %d - Il conduttore si impegna a corrispondere il canone pattuito entro il giorno cinque.) Tj ET\n", y, line+1)
	}
	page.WriteString("BT /F1 10 Tf 72 150 Td (Letto, approvato e sottoscritto.) Tj ET\n")
	page.WriteString("72 110 m 250 110 l S\nBT /F1 9 Tf 72 98 Td (Il locatore) Tj ET\n")

	content := page.String()
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R 5 0 R] /Count 2 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}

	var pdf strings.Builder
	pdf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for index, object := range objects {
		offsets[index] = pdf.Len()
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", index+1, object)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)

	path := filepath.Join(t.TempDir(), "contratto-di-locazione-2026-via-roma-12.pdf")
	if err := os.WriteFile(path, []byte(pdf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestScreenshotOfTheSeal renders the page canvas alone at a large size, so the
// stamp drawing can be compared with the PDF the signer produces.
func TestScreenshotOfTheSeal(t *testing.T) {
	directory := os.Getenv("TREBARUNA_SCREENSHOTS")
	if directory == "" {
		t.Skip("set TREBARUNA_SCREENSHOTS to a directory to write screenshots")
	}
	app := test.NewTempApp(t)
	app.Settings().SetTheme(NewAppTheme(DefaultPalette()))

	preview := application.NewPreviewPage(NewPopplerRenderer(), application.InkFinder{})
	result, err := preview.Execute(t.Context(), writeSampleContract(t), 1, application.DefaultSealSize())
	if err != nil {
		t.Fatal(err)
	}
	page, _, err := image.Decode(bytes.NewReader(result.Preview.PNG))
	if err != nil {
		t.Fatal(err)
	}
	pageCanvas := NewPageCanvas(result.Geometry, result.Preview.Ink, page, result.SealRect,
		SealIdentity{Name: "MARIA DEL CARMEN LOPEZ GARCIA MARTINEZ", Identifier: "IDCES-00000000X"}, nil)

	window := test.NewTempWindow(t, pageCanvas)
	window.Resize(fyne.NewSize(1200, 1700))
	capture(t, window, filepath.Join(directory, "seal-large.png"))
}
