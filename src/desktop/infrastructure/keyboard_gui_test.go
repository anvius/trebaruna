//go:build gui

package infrastructure

import (
	"math"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

// TestTheSealGrowsAndShrinksFromTheKeyboard: + and - do what the corner
// handle does, keeping the proportions, never below the smallest seal the
// identity fits in (WCAG 2.5.7, an alternative to dragging).
func TestTheSealGrowsAndShrinksFromTheKeyboard(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	pages := fixture.desktop.pages
	fixture.desktop.form.setDocument("/tmp/contratto.pdf")
	settle(t, func() bool { return pages.canvas != nil })
	test.TempWidgetRenderer(t, pages.canvas).Layout(fyne.NewSize(600, 800))

	before := pages.canvas.Rect()
	pages.canvas.TypedRune('+')
	grown := pages.canvas.Rect()
	if math.Abs(grown.Width()-before.Width()-4) > 0.5 || math.Abs(grown.Height()/grown.Width()-before.Height()/before.Width()) > 0.02 {
		t.Errorf("+ made %vx%v of %vx%v", grown.Width(), grown.Height(), before.Width(), before.Height())
	}
	for range 10 {
		pages.canvas.TypedRune('-')
	}
	if shrunk := pages.canvas.Rect(); shrunk.Width() < 63.9 || shrunk.Height() < 47.9 {
		t.Errorf("- shrank the seal to %vx%v, below 64x48", shrunk.Width(), shrunk.Height())
	}
	pages.canvas.TypedRune('x')
}

// TestTabReachesThePageAndTheSignButton: the keyboard alone gets to the
// seal and to signing.
func TestTabReachesThePageAndTheSignButton(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form, pages := fixture.desktop.form, fixture.desktop.pages
	form.setDocument("/tmp/contratto.pdf")
	settle(t, func() bool { return pages.canvas != nil })

	canvas := fixture.desktop.window.Canvas()
	reached := map[fyne.Focusable]bool{}
	for range 80 {
		canvas.FocusNext()
		if focused := canvas.Focused(); focused != nil {
			reached[focused] = true
		}
	}
	if !reached[pages.canvas] {
		t.Error("Tab never reaches the page, where the seal is moved")
	}
	if !reached[fyne.Focusable(form.signButton)] {
		t.Error("Tab never reaches the sign button")
	}
}

// TestScreenReadersGetNamesNotIconFiles: the page arrows have names, and
// the page says what the line under it says, its warning included.
func TestScreenReadersGetNamesNotIconFiles(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	pages := fixture.desktop.pages
	fixture.desktop.form.setDocument("/tmp/contratto.pdf")
	settle(t, func() bool { return pages.canvas != nil })
	if pages.previous.AccessibilityLabel() != pages.messages.PreviousPage || pages.next.AccessibilityLabel() != pages.messages.NextPage {
		t.Errorf("page arrows say %q and %q", pages.previous.AccessibilityLabel(), pages.next.AccessibilityLabel())
	}
	if label := pages.canvas.AccessibilityLabel(); label == "" || label != pages.hint.Text {
		t.Errorf("the page says %q, the line under it %q", label, pages.hint.Text)
	}
}
