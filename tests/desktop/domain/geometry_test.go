package domain_test

import (
	"testing"

	"codeberg.org/anvius/trebaruna/src/desktop/domain"
)

func geometry(t *testing.T) domain.PageGeometry {
	t.Helper()
	// A4 at 300x424 cells: exactly the shape poppler produces at our defaults.
	built, err := domain.NewPageGeometry(595.28, 841.89, 300, 424)
	if err != nil {
		t.Fatalf("NewPageGeometry: %v", err)
	}
	return built
}

// TestCandidateRectFlipsTheYAxis is the regression guard for the classic bug:
// raster Y grows downwards, PDF Y grows upwards.
func TestCandidateRectFlipsTheYAxis(t *testing.T) {
	g := geometry(t)

	// A candidate at the very top of the raster (y = 0) must map to the TOP of
	// the PDF page, i.e. a high Y in points.
	top := g.CandidateRect(domain.Candidate{X: 0, Y: 0, Width: 100, Height: 35})
	if top.Y+top.Height < 700 {
		t.Errorf("top candidate mapped to Y=%v, expected near the top of an 842pt page", top.Y)
	}

	// A candidate at the bottom of the raster must map to a low Y.
	bottom := g.CandidateRect(domain.Candidate{X: 0, Y: 389, Width: 100, Height: 35})
	if bottom.Y > 120 {
		t.Errorf("bottom candidate mapped to Y=%v, expected near the page bottom", bottom.Y)
	}
}

func TestCandidateRectPreservesSize(t *testing.T) {
	g := geometry(t)

	candidate := domain.Candidate{X: 30, Y: 40, Width: 100, Height: 35}
	rect := g.CandidateRect(candidate)

	expectedWidth := 100 * g.PointsPerCellX()
	expectedHeight := 35 * g.PointsPerCellY()

	if diff := rect.Width - expectedWidth; diff > 0.01 || diff < -0.01 {
		t.Errorf("width = %v, want %v", rect.Width, expectedWidth)
	}
	if diff := rect.Height - expectedHeight; diff > 0.01 || diff < -0.01 {
		t.Errorf("height = %v, want %v", rect.Height, expectedHeight)
	}
}

func TestClampKeepsTheSealInsideThePage(t *testing.T) {
	g := geometry(t)

	// Dragged far past the top-right corner.
	overTheEdge := domain.SealRect{LowerLeftX: 900, LowerLeftY: 900, UpperRightX: 1100, UpperRightY: 970}
	clamped := g.Clamp(overTheEdge)

	if !g.Valid(clamped) {
		t.Errorf("clamped rectangle is still invalid: %+v", clamped)
	}
	if clamped.UpperRightX > g.WidthPoints+0.01 {
		t.Errorf("clamped X overflows the page: %v", clamped.UpperRightX)
	}
	if clamped.UpperRightY > g.HeightPoints+0.01 {
		t.Errorf("clamped Y overflows the page: %v", clamped.UpperRightY)
	}
	if clamped.Width() != overTheEdge.Width() {
		t.Errorf("clamping changed the width: %v -> %v", overTheEdge.Width(), clamped.Width())
	}
}

func TestClampHandlesNegativeCoordinates(t *testing.T) {
	g := geometry(t)

	negative := domain.SealRect{LowerLeftX: -50, LowerLeftY: -80, UpperRightX: 150, UpperRightY: 10}
	clamped := g.Clamp(negative)

	if clamped.LowerLeftX < 0 || clamped.LowerLeftY < 0 {
		t.Errorf("negative coordinates survived clamping: %+v", clamped)
	}
}

func TestMoveByTranslatesBothCorners(t *testing.T) {
	rect := domain.SealRect{LowerLeftX: 100, LowerLeftY: 200, UpperRightX: 300, UpperRightY: 270}

	moved := rect.MoveBy(10, -20)
	if moved.LowerLeftX != 110 || moved.LowerLeftY != 180 {
		t.Errorf("lower-left = (%v,%v), want (110,180)", moved.LowerLeftX, moved.LowerLeftY)
	}
	if moved.UpperRightX != 310 || moved.UpperRightY != 250 {
		t.Errorf("upper-right = (%v,%v), want (310,250)", moved.UpperRightX, moved.UpperRightY)
	}
	if moved.Width() != rect.Width() || moved.Height() != rect.Height() {
		t.Error("moving changed the size")
	}
}

func TestResizeKeepsTheLowerLeftCorner(t *testing.T) {
	rect := domain.SealRect{LowerLeftX: 100, LowerLeftY: 200, UpperRightX: 300, UpperRightY: 270}

	resized := rect.Resize(250, 90)
	if resized.LowerLeftX != 100 || resized.LowerLeftY != 200 {
		t.Error("resize moved the anchor corner")
	}
	if resized.Width() != 250 || resized.Height() != 90 {
		t.Errorf("size = %vx%v, want 250x90", resized.Width(), resized.Height())
	}
}

func TestBoxStringUsesCLISyntax(t *testing.T) {
	rect := domain.SealRect{LowerLeftX: 100, LowerLeftY: 600, UpperRightX: 300, UpperRightY: 700}
	got := rect.BoxString()
	want := "100.0,600.0,300.0,700.0"
	if got != want {
		t.Errorf("BoxString() = %q, want %q", got, want)
	}
}

func TestToCandidateRoundTrip(t *testing.T) {
	g := geometry(t)

	original := domain.SealRect{LowerLeftX: 120, LowerLeftY: 300, UpperRightX: 320, UpperRightY: 370}
	candidate := g.ToCandidate(original)
	back := g.CandidateRect(candidate)

	// Round-tripping through integer cells loses a little precision; anything
	// beyond two points means the conversion is wrong, not merely rounded.
	if diff := back.X - original.LowerLeftX; diff > 2 || diff < -2 {
		t.Errorf("X drifted: %v -> %v", original.LowerLeftX, back.X)
	}
	if diff := back.Y - original.LowerLeftY; diff > 2 || diff < -2 {
		t.Errorf("Y drifted: %v -> %v", original.LowerLeftY, back.Y)
	}
}

func TestValidRejectsDegenerateRectangles(t *testing.T) {
	g := geometry(t)

	if g.Valid(domain.SealRect{LowerLeftX: 100, LowerLeftY: 100, UpperRightX: 100, UpperRightY: 200}) {
		t.Error("zero width must be invalid")
	}
	if g.Valid(domain.SealRect{LowerLeftX: 100, LowerLeftY: 100, UpperRightX: 200, UpperRightY: 100}) {
		t.Error("zero height must be invalid")
	}
	if g.Valid(domain.SealRect{LowerLeftX: 100, LowerLeftY: 100, UpperRightX: 700, UpperRightY: 200}) {
		t.Error("rectangle overflowing the page width must be invalid")
	}
}

func TestNewPageGeometryRejectsBadSizes(t *testing.T) {
	if _, err := domain.NewPageGeometry(0, 800, 100, 100); err == nil {
		t.Error("zero page width must fail")
	}
	if _, err := domain.NewPageGeometry(600, 800, 0, 100); err == nil {
		t.Error("zero raster width must fail")
	}
}
