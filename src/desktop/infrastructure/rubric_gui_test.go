//go:build gui

package infrastructure

import (
	"bytes"
	"image"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// writeRubricImage writes a 300x100 PNG.
func writeRubricImage(t *testing.T) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, image.NewNRGBA(image.Rect(0, 0, 300, 100))); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "firma.png")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// near compares seal widths, which the page fit rounds.
func near(width, want float64) bool { return math.Abs(width-want) < 1 }

// TestARubricWidensTheSealAndReachesTheSigner (ADR-0012): the page proposes
// a seal wide enough for it, the preview draws it left of the data, the
// choice is remembered, and the signer receives it.
func TestARubricWidensTheSealAndReachesTheSigner(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form, pages := fixture.desktop.form, fixture.desktop.pages
	form.setDocument("/tmp/contratto.pdf")
	settle(t, func() bool { return pages.canvas != nil })
	if !form.rubricBox.Visible() || !near(pages.canvas.Rect().Width(), 64) {
		t.Fatalf("rubric row shown %t, seal %v wide", form.rubricBox.Visible(), pages.canvas.Rect().Width())
	}

	rubric := writeRubricImage(t)
	form.setRubric(rubric)
	settle(t, func() bool { return pages.canvas != nil && near(pages.canvas.Rect().Width(), 160) })
	if !form.rubricRemove.Visible() || form.preferences.String(preferenceRubric) != rubric {
		t.Error("the chosen rubric is not shown or remembered")
	}
	renderer := test.TempWidgetRenderer(t, pages.canvas).(*pageCanvasRenderer)
	renderer.Layout(fyne.NewSize(600, 800))
	if !renderer.rubric.Visible() || renderer.bar.Position().X <= renderer.rubric.Position().X+renderer.rubric.Size().Width {
		t.Errorf("preview: rubric shown %t at %v %v, bar at %v", renderer.rubric.Visible(),
			renderer.rubric.Position(), renderer.rubric.Size(), renderer.bar.Position())
	}

	form.setCertificate("/tmp/rossi.p12")
	form.passphrase.SetText("segreto")
	settle(t, func() bool { return form.summary != nil })
	test.Tap(form.signButton)
	if intent := <-fixture.signer.intents; intent.RubricPath != rubric || !near(intent.Seal.Rect.Width(), 160) {
		t.Errorf("intent rubric %q, seal %v wide", intent.RubricPath, intent.Seal.Rect.Width())
	}

	form.removeRubric()
	settle(t, func() bool { return pages.canvas != nil && near(pages.canvas.Rect().Width(), 64) })
	if form.rubricPath != "" || form.preferences.String(preferenceRubric) != "" {
		t.Error("the rubric was not removed")
	}
}

// TestAnImageThatCannotBeARubricIsRefused before anything is signed.
func TestAnImageThatCannotBeARubricIsRefused(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	form.setDocument("/tmp/contratto.pdf")
	text := filepath.Join(t.TempDir(), "firma.png")
	os.WriteFile(text, []byte("not an image"), 0o600)
	form.setRubric(text)
	if form.rubricPath != "" || form.status.Importance != widget.DangerImportance || form.status.Text != form.m.RubricInvalid {
		t.Errorf("path %q, status %q", form.rubricPath, form.status.Text)
	}
}

// TestTheRubricIsOnlyOfferedForAVisibleSeal, and is not sent without one.
func TestTheRubricIsOnlyOfferedForAVisibleSeal(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	form.setDocument("/tmp/contratto.pdf")
	form.setRubric(writeRubricImage(t))
	form.invisible.SetChecked(true)
	if form.rubricBox.Visible() {
		t.Error("an invisible signature offers a rubric")
	}
	form.invisible.SetChecked(false)
	form.setDocument("/tmp/offerta.docx")
	if form.rubricBox.Visible() || form.format != domain.FormatOOXML {
		t.Error("an Office file offers a rubric")
	}
}
