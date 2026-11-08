package domain_test

import (
	"strings"
	"testing"

	"codeberg.org/anvius/pignus/src/desktop/domain"
)

// blankPage builds an empty A4-ish map at a fixed raster size.
func blankPage(width, height int) domain.InkMap {
	map_, err := domain.NewInkMap(width, height, make([]float64, width*height))
	if err != nil {
		panic(err)
	}
	return map_
}

// paint fills a block of cells, standing in for a patch of printed text.
func paint(cells []float64, width, height, x0, y0, x1, y1 int, density float64) {
	for y := y0; y < y1 && y < height; y++ {
		for x := x0; x < x1 && x < width; x++ {
			cells[y*width+x] = density
		}
	}
}

func TestNewInkMapRejectsBadInput(t *testing.T) {
	if _, err := domain.NewInkMap(0, 10, nil); err == nil {
		t.Error("zero width must fail")
	}
	if _, err := domain.NewInkMap(4, 4, []float64{1, 2, 3}); err == nil {
		t.Error("wrong cell count must fail")
	}
	if _, err := domain.NewInkMap(2, 2, []float64{0, 1.5, 0, 0}); err == nil {
		t.Error("density above 1 must fail")
	}
}

func TestInkInMeasuresRectangles(t *testing.T) {
	width, height := 10, 10
	cells := make([]float64, width*height)
	for y := 0; y < 5; y++ {
		for x := 0; x < 10; x++ {
			cells[y*width+x] = 1
		}
	}
	map_, err := domain.NewInkMap(width, height, cells)
	if err != nil {
		t.Fatal(err)
	}

	if got := map_.InkIn(0, 0, 10, 5); got != 1 {
		t.Errorf("fully inked half = %v, want 1", got)
	}
	if got := map_.InkIn(0, 5, 10, 5); got != 0 {
		t.Errorf("blank half = %v, want 0", got)
	}
	// The rectangle is clipped instead of panicking.
	if got := map_.InkIn(-5, -5, 100, 100); got < 0 || got > 1 {
		t.Errorf("clipped rectangle = %v, want 0..1", got)
	}
}

func TestFindFreeSpacePrefersBottomRight(t *testing.T) {
	map_ := blankPage(300, 424)

	candidates, err := map_.FindFreeSpace(100, 35, 3)
	if err != nil {
		t.Fatalf("FindFreeSpace: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatal("no candidates on a blank page")
	}
	if candidates[0].Zone != domain.ZoneBottomRight {
		t.Errorf("first zone = %s, want bottom-right", candidates[0].Zone)
	}
	if candidates[0].Ink != 0 {
		t.Errorf("blank page candidate has ink %v", candidates[0].Ink)
	}
}

func TestFindFreeSpaceAvoidsText(t *testing.T) {
	width, height := 300, 424
	cells := make([]float64, width*height)

	// Fill the bottom-right corner with text, the place the search prefers.
	paint(cells, width, height, 180, 360, 300, 420, 0.9)

	map_, err := domain.NewInkMap(width, height, cells)
	if err != nil {
		t.Fatal(err)
	}

	candidates, err := map_.FindFreeSpace(100, 35, 3)
	if err != nil {
		t.Fatalf("FindFreeSpace: %v", err)
	}

	for _, candidate := range candidates {
		if candidate.Ink > 0.08 {
			t.Errorf("candidate %+v covers text", candidate)
		}
	}

	// It may legitimately stay bottom-right, but it must sit just above the
	// painted block, never inside it. The block starts at y=360, so a candidate
	// ending at 350 is correct; one starting at 360 is not.
	first := candidates[0]
	if first.X > 170 && first.Y+first.Height > 355 {
		t.Errorf("chosen candidate overlaps the text block: %+v", first)
	}
}

func TestFindFreeSpaceFailsOnAFullPage(t *testing.T) {
	width, height := 100, 100
	cells := make([]float64, width*height)
	for index := range cells {
		cells[index] = 1
	}
	map_, err := domain.NewInkMap(width, height, cells)
	if err != nil {
		t.Fatal(err)
	}

	_, err = map_.FindFreeSpace(30, 20, 1)
	if err == nil {
		t.Fatal("a fully inked page must not yield a candidate")
	}
	if !strings.Contains(err.Error(), "no empty space") {
		t.Errorf("error should explain the cause, got %v", err)
	}
}

func TestFindFreeSpaceRejectsSealLargerThanPage(t *testing.T) {
	map_ := blankPage(100, 100)
	if _, err := map_.FindFreeSpace(200, 50, 1); err == nil {
		t.Fatal("a seal wider than the page must fail")
	}
}

func TestFindFreeSpaceReturnsSpreadCandidates(t *testing.T) {
	map_ := blankPage(300, 424)

	candidates, err := map_.FindFreeSpace(100, 35, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) < 2 {
		t.Skip("page offers only one distinct area")
	}

	// The first two suggestions must not be the same spot.
	first, second := candidates[0], candidates[1]
	if abs(first.X-second.X) < 10 && abs(first.Y-second.Y) < 10 {
		t.Errorf("candidates are neighbours, not alternatives: %+v / %+v", first, second)
	}
}

func TestFindFreeSpaceIsDeterministic(t *testing.T) {
	map_ := blankPage(200, 300)

	first, err := map_.FindFreeSpace(80, 30, 3)
	if err != nil {
		t.Fatal(err)
	}
	second, err := map_.FindFreeSpace(80, 30, 3)
	if err != nil {
		t.Fatal(err)
	}

	for index := range first {
		if first[index] != second[index] {
			t.Fatalf("search is not deterministic at %d: %+v vs %+v", index, first[index], second[index])
		}
	}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
