package domain_test

import (
	"math"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

func a4Geometry(t *testing.T) domain.PageGeometry {
	t.Helper()
	geometry, err := domain.NewPageGeometry(595.28, 841.89, 298, 421)
	if err != nil {
		t.Fatal(err)
	}
	return geometry
}

func near(left, right float64) bool { return math.Abs(left-right) < 0.01 }

func TestAPortraitPageIsCentredHorizontallyInAWideFrame(t *testing.T) {
	fit := a4Geometry(t).FitInto(1000, 841.89)

	if !near(fit.Scale, 1) {
		t.Errorf("scale = %v, want the height to decide (1)", fit.Scale)
	}
	if !near(fit.OffsetX, (1000-595.28)/2) || !near(fit.OffsetY, 0) {
		t.Errorf("offset = %v,%v, want the page centred horizontally", fit.OffsetX, fit.OffsetY)
	}
	area := fit.PageArea()
	if !near(area.Width, 595.28) || !near(area.Height, 841.89) {
		t.Errorf("page area = %+v", area)
	}
}

func TestAnEmptyFrameHasNoFit(t *testing.T) {
	fit := a4Geometry(t).FitInto(0, 500)
	if fit.Scale != 0 {
		t.Fatalf("scale = %v, want 0 for a frame with no width", fit.Scale)
	}
	if _, _, inside := fit.ToPage(10, 10); inside {
		t.Error("nothing can be inside a page that is not drawn")
	}
	rect := domain.SealRect{LowerLeftX: 1, LowerLeftY: 1, UpperRightX: 65, UpperRightY: 49}
	if fit.Move(rect, 10, 10) != rect || fit.Grow(rect, 10, 10) != rect {
		t.Error("moving or growing without a fit must leave the seal alone")
	}
}

func TestScreenAndPageCoordinatesRoundTrip(t *testing.T) {
	fit := a4Geometry(t).FitInto(700, 760)
	rect := domain.SealRect{LowerLeftX: 400, LowerLeftY: 60, UpperRightX: 464, UpperRightY: 108}

	screen := fit.ToScreen(rect)
	pointX, pointY, inside := fit.ToPage(screen.X, screen.Y)
	if !inside {
		t.Fatal("the seal's top-left corner must be on the page")
	}
	if !near(pointX, rect.LowerLeftX) || !near(pointY, rect.UpperRightY) {
		t.Errorf("top-left corner came back as %v,%v, want %v,%v",
			pointX, pointY, rect.LowerLeftX, rect.UpperRightY)
	}
	if !near(screen.Width, 64*fit.Scale) || !near(screen.Height, 48*fit.Scale) {
		t.Errorf("screen size = %vx%v", screen.Width, screen.Height)
	}
}

func TestAPointOnTheFrameIsNotOnThePage(t *testing.T) {
	fit := a4Geometry(t).FitInto(1000, 841.89)
	if _, _, inside := fit.ToPage(10, 400); inside {
		t.Error("the margin left of a centred page is not paper")
	}
	if _, _, inside := fit.ToPage(500, 400); !inside {
		t.Error("the middle of the frame is on the page")
	}
}

func TestAClickCentresTheSealUnderThePointer(t *testing.T) {
	fit := a4Geometry(t).FitInto(595.28, 841.89)

	rect := fit.CentredAt(300, 400, 64, 48)

	if !near(rect.Width(), 64) || !near(rect.Height(), 48) {
		t.Fatalf("size = %vx%v, want 64x48", rect.Width(), rect.Height())
	}
	screen := fit.ToScreen(rect)
	if !near(screen.X+screen.Width/2, 300) || !near(screen.Y+screen.Height/2, 400) {
		t.Errorf("centre = %v,%v, want the click at 300,400",
			screen.X+screen.Width/2, screen.Y+screen.Height/2)
	}
}

func TestAClickNearTheEdgeKeepsTheSealWhole(t *testing.T) {
	geometry := a4Geometry(t)
	fit := geometry.FitInto(595.28, 841.89)

	rect := fit.CentredAt(594, 841, 64, 48)
	if !geometry.Valid(rect) {
		t.Fatalf("rect %+v leaves the page", rect)
	}
	if !near(rect.Width(), 64) {
		t.Errorf("clamping must keep the size, got width %v", rect.Width())
	}
}

func TestDraggingMovesTheSealWithThePointer(t *testing.T) {
	fit := a4Geometry(t).FitInto(297.64, 420.945) // half scale
	rect := domain.SealRect{LowerLeftX: 100, LowerLeftY: 100, UpperRightX: 164, UpperRightY: 148}

	moved := fit.Move(rect, 10, 20) // right and down on screen

	if !near(moved.LowerLeftX, 120) {
		t.Errorf("x = %v, want 20 pt to the right (10 px at half scale)", moved.LowerLeftX)
	}
	if !near(moved.LowerLeftY, 60) {
		t.Errorf("y = %v, want 40 pt lower: screen down is PDF down", moved.LowerLeftY)
	}
}

func TestDraggingPastTheEdgeStopsAtTheEdge(t *testing.T) {
	geometry := a4Geometry(t)
	fit := geometry.FitInto(595.28, 841.89)
	rect := domain.SealRect{LowerLeftX: 500, LowerLeftY: 10, UpperRightX: 564, UpperRightY: 58}

	moved := fit.Move(rect, 500, 500)
	if !geometry.Valid(moved) || !near(moved.UpperRightX, 595.28) || !near(moved.LowerLeftY, 0) {
		t.Errorf("moved = %+v, want it pinned to the bottom-right corner", moved)
	}
}

func TestGrowingKeepsTheTopLeftCorner(t *testing.T) {
	fit := a4Geometry(t).FitInto(595.28, 841.89)
	rect := domain.SealRect{LowerLeftX: 100, LowerLeftY: 400, UpperRightX: 164, UpperRightY: 448}

	grown := fit.Grow(rect, 36, 12)

	if !near(grown.LowerLeftX, 100) || !near(grown.UpperRightY, 448) {
		t.Errorf("top-left moved: %+v", grown)
	}
	if !near(grown.Width(), 100) || !near(grown.Height(), 60) {
		t.Errorf("size = %vx%v, want 100x60", grown.Width(), grown.Height())
	}
}

func TestASealCannotShrinkBelowTheIdentityItCarries(t *testing.T) {
	fit := a4Geometry(t).FitInto(595.28, 841.89)
	rect := domain.SealRect{LowerLeftX: 100, LowerLeftY: 400, UpperRightX: 164, UpperRightY: 448}

	shrunk := fit.Grow(rect, -50, -50)
	if !near(shrunk.Width(), domain.MinimumSealWidth) || !near(shrunk.Height(), domain.MinimumSealHeight) {
		t.Errorf("size = %vx%v, want the minimum", shrunk.Width(), shrunk.Height())
	}
}

func TestASealCannotGrowPastThePage(t *testing.T) {
	geometry := a4Geometry(t)
	fit := geometry.FitInto(595.28, 841.89)
	rect := domain.SealRect{LowerLeftX: 500, LowerLeftY: 10, UpperRightX: 564, UpperRightY: 58}

	grown := fit.Grow(rect, 400, 400)
	if !geometry.Valid(grown) {
		t.Errorf("grown = %+v leaves the page", grown)
	}
}

func TestASealOnTextIsReported(t *testing.T) {
	geometry := a4Geometry(t)
	cells := make([]float64, 298*421)
	// A paragraph of solid ink across the top fifth of the page.
	for y := 0; y < 84; y++ {
		for x := 0; x < 298; x++ {
			cells[y*298+x] = 1
		}
	}
	ink, err := domain.NewInkMap(298, 421, cells)
	if err != nil {
		t.Fatal(err)
	}

	onText := domain.SealRect{LowerLeftX: 100, LowerLeftY: 760, UpperRightX: 164, UpperRightY: 808}
	onPaper := domain.SealRect{LowerLeftX: 100, LowerLeftY: 100, UpperRightX: 164, UpperRightY: 148}

	if !geometry.Covers(ink, onText) {
		t.Error("a seal on the paragraph must be reported")
	}
	if geometry.Covers(ink, onPaper) {
		t.Error("a seal on blank paper is fine")
	}
}

func TestRectangleContainment(t *testing.T) {
	box := domain.Rectangle{X: 10, Y: 10, Width: 20, Height: 10}
	if !box.Contains(10, 10) || !box.Contains(30, 20) || box.Contains(31, 15) || box.Contains(15, 9) {
		t.Error("containment must include the edges and nothing beyond")
	}
}
