//go:build gui

package infrastructure_test

// Interaction tests for the page canvas, driven through Fyne's test driver.
//
// The canvas is laid out at exactly the page size in points, so one screen
// unit is one PDF point and the expected rectangles can be read off directly.

import (
	"image"
	"image/color"
	"math"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/test"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"
)

const pageWidth, pageHeight = 595.28, 841.89

// startingSeal sits in the bottom-right area: x 480..544, y 60..108 in points,
// which on screen is x 480..544, y 733.89..781.89.
var startingSeal = domain.SealRect{LowerLeftX: 480, LowerLeftY: 60, UpperRightX: 544, UpperRightY: 108}

func newCanvas(t *testing.T, ink domain.InkMap) (*infrastructure.PageCanvas, *[]domain.SealRect) {
	t.Helper()
	test.NewTempApp(t)

	geometry, err := domain.NewPageGeometry(pageWidth, pageHeight, 298, 421)
	if err != nil {
		t.Fatal(err)
	}
	page := image.NewRGBA(image.Rect(0, 0, 298, 421))
	for index := range page.Pix {
		page.Pix[index] = 255
	}

	var changes []domain.SealRect
	pageCanvas := infrastructure.NewPageCanvas(geometry, ink, page, startingSeal,
		infrastructure.SealIdentity{Name: "MARIO ROSSI", Identifier: "TINIT-RSSMRA80A01H501U"},
		func(rect domain.SealRect) { changes = append(changes, rect) })
	test.WidgetRenderer(pageCanvas)
	pageCanvas.Resize(fyne.NewSize(pageWidth, pageHeight))
	return pageCanvas, &changes
}

func blankInk(t *testing.T) domain.InkMap {
	t.Helper()
	ink, err := domain.NewInkMap(298, 421, make([]float64, 298*421))
	if err != nil {
		t.Fatal(err)
	}
	return ink
}

func closeTo(left, right float64) bool { return math.Abs(left-right) < 0.6 }

// drag sends one drag step the way the desktop driver does: Position is where
// the pointer is now, Dragged is how far it moved since the previous event.
func drag(target *infrastructure.PageCanvas, fromX, fromY, deltaX, deltaY float32) {
	target.Dragged(&fyne.DragEvent{
		PointEvent: fyne.PointEvent{Position: fyne.NewPos(fromX+deltaX, fromY+deltaY)},
		Dragged:    fyne.NewDelta(deltaX, deltaY),
	})
	target.DragEnd()
}

func TestAClickOnThePagePutsTheSealUnderThePointer(t *testing.T) {
	pageCanvas, changes := newCanvas(t, blankInk(t))

	test.TapAt(pageCanvas, fyne.NewPos(300, 400))

	rect := pageCanvas.Rect()
	centreX := (rect.LowerLeftX + rect.UpperRightX) / 2
	centreY := pageHeight - (rect.LowerLeftY+rect.UpperRightY)/2
	if !closeTo(centreX, 300) || !closeTo(centreY, 400) {
		t.Errorf("seal centre = %.1f,%.1f on screen, want 300,400", centreX, centreY)
	}
	if !closeTo(rect.Width(), 64) || !closeTo(rect.Height(), 48) {
		t.Errorf("a click must keep the size, got %.1fx%.1f", rect.Width(), rect.Height())
	}
	if len(*changes) != 1 || (*changes)[0] != rect {
		t.Errorf("the window must hear about the move once, got %v", *changes)
	}
}

func TestAClickBesideThePageDoesNothing(t *testing.T) {
	pageCanvas, changes := newCanvas(t, blankInk(t))
	pageCanvas.Resize(fyne.NewSize(1000, pageHeight)) // page centred, margins left and right

	test.TapAt(pageCanvas, fyne.NewPos(20, 400))

	if pageCanvas.Rect() != startingSeal || len(*changes) != 0 {
		t.Errorf("a click on the margin moved the seal to %+v", pageCanvas.Rect())
	}
}

func TestDraggingTheSealMovesIt(t *testing.T) {
	pageCanvas, _ := newCanvas(t, blankInk(t))

	drag(pageCanvas, 500, 750, -100, -200) // grab inside, move left and up

	rect := pageCanvas.Rect()
	if !closeTo(rect.LowerLeftX, 380) || !closeTo(rect.LowerLeftY, 260) {
		t.Errorf("seal at %.1f,%.1f, want 380,260", rect.LowerLeftX, rect.LowerLeftY)
	}
	if !closeTo(rect.Width(), 64) {
		t.Errorf("moving must not resize, width %.1f", rect.Width())
	}
}

func TestDraggingTheCornerEnlargesTheSeal(t *testing.T) {
	pageCanvas, _ := newCanvas(t, blankInk(t))

	drag(pageCanvas, 542, 779.89, 36, 12) // the handle sits in the bottom-right corner

	rect := pageCanvas.Rect()
	if !closeTo(rect.Width(), 100) || !closeTo(rect.Height(), 60) {
		t.Errorf("size = %.1fx%.1f, want 100x60", rect.Width(), rect.Height())
	}
	if !closeTo(rect.LowerLeftX, 480) || !closeTo(rect.UpperRightY, 108) {
		t.Errorf("the top-left corner moved: %+v", rect)
	}
}

func TestDraggingOnEmptyPaperPicksTheSealUp(t *testing.T) {
	pageCanvas, _ := newCanvas(t, blankInk(t))

	drag(pageCanvas, 200, 200, 10, 0)

	rect := pageCanvas.Rect()
	centreX := (rect.LowerLeftX + rect.UpperRightX) / 2
	if !closeTo(centreX, 210) {
		t.Errorf("seal centre x = %.1f, want it dropped at 200 and carried to 210", centreX)
	}
}

func TestDraggingFromBesideThePageIsIgnored(t *testing.T) {
	pageCanvas, _ := newCanvas(t, blankInk(t))
	pageCanvas.Resize(fyne.NewSize(1000, pageHeight))

	drag(pageCanvas, 20, 400, 100, 0)

	if pageCanvas.Rect() != startingSeal {
		t.Errorf("a drag that started on the margin moved the seal to %+v", pageCanvas.Rect())
	}
}

func TestArrowKeysNudgeTheSeal(t *testing.T) {
	pageCanvas, _ := newCanvas(t, blankInk(t))

	pageCanvas.TypedKey(&fyne.KeyEvent{Name: fyne.KeyLeft})
	pageCanvas.TypedKey(&fyne.KeyEvent{Name: fyne.KeyUp})
	pageCanvas.TypedKey(&fyne.KeyEvent{Name: fyne.KeyA}) // ignored

	rect := pageCanvas.Rect()
	if !closeTo(rect.LowerLeftX, 478) || !closeTo(rect.LowerLeftY, 62) {
		t.Errorf("seal at %.1f,%.1f, want 478,62", rect.LowerLeftX, rect.LowerLeftY)
	}
}

func TestTheCursorAnnouncesWhatAPressWillDo(t *testing.T) {
	pageCanvas, _ := newCanvas(t, blankInk(t))

	cases := []struct {
		x, y float32
		want desktop.Cursor
	}{
		{542, 779.89, desktop.NWSEResizeCursor},
		{500, 750, desktop.PointerCursor},
		{200, 200, desktop.CrosshairCursor},
	}
	for _, testCase := range cases {
		pageCanvas.MouseMoved(&desktop.MouseEvent{PointEvent: fyne.PointEvent{Position: fyne.NewPos(testCase.x, testCase.y)}})
		if got := pageCanvas.Cursor(); got != testCase.want {
			t.Errorf("cursor at %v,%v = %v, want %v", testCase.x, testCase.y, got, testCase.want)
		}
	}
	pageCanvas.MouseOut()
	if pageCanvas.Cursor() != desktop.DefaultCursor {
		t.Error("outside the canvas the cursor is the default")
	}
}

func TestASealOnTextIsFlagged(t *testing.T) {
	cells := make([]float64, 298*421)
	for y := 0; y < 60; y++ { // a heading across the top of the page
		for x := 0; x < 298; x++ {
			cells[y*298+x] = 1
		}
	}
	ink, err := domain.NewInkMap(298, 421, cells)
	if err != nil {
		t.Fatal(err)
	}
	pageCanvas, _ := newCanvas(t, ink)

	if pageCanvas.CoversText() {
		t.Fatal("the starting seal sits on blank paper")
	}
	test.TapAt(pageCanvas, fyne.NewPos(300, 40))
	if !pageCanvas.CoversText() {
		t.Error("a seal on the heading must be flagged")
	}
}

func TestTheSealPrintsTheHolderWithoutOverlappingLines(t *testing.T) {
	pageCanvas, _ := newCanvas(t, blankInk(t))
	pageCanvas.SetIdentity(infrastructure.SealIdentity{
		Name: "MARIA DEL CARMEN LOPEZ GARCIA MARTINEZ", Identifier: "IDCES-00000000X",
	})

	var lines []*canvas.Text
	for _, object := range test.WidgetRenderer(pageCanvas).Objects() {
		if text, ok := object.(*canvas.Text); ok {
			lines = append(lines, text)
		}
	}
	if len(lines) < 4 {
		t.Fatalf("got %d text lines, want a wrapped name plus the details", len(lines))
	}
	for index := 1; index < len(lines); index++ {
		previous, current := lines[index-1], lines[index]
		if current.Position().Y < previous.Position().Y+previous.TextSize*0.8 {
			t.Errorf("line %q overprints %q", current.Text, previous.Text)
		}
	}
	if lines[0].Color != (color.NRGBA{R: 16, G: 20, B: 26, A: 255}) {
		t.Errorf("the name must use the ink the signer prints, got %v", lines[0].Color)
	}
}
