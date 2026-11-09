// Package domain holds the page-space rules: where a seal may sit, and which
// empty gap on the page fits it.
//
// Nothing here knows about Fyne, PDFs or images: an InkMap is just a grid of
// numbers saying "how much ink is here". That keeps the geometry testable
// without rendering a single document.
package domain

import (
	"fmt"
	"math"
)

// InkMap is a raster of a page where each cell holds an ink density in 0..1.
//
// Zero means blank paper, one means fully covered. Coordinates are cells, with
// the origin at the top-left corner, matching how a rasterised page is read.
type InkMap struct {
	width  int
	height int
	// prefix is a summed-area table over cells: prefix[(y*(w+1))+x] holds the
	// ink of every cell above and to the left, which turns any rectangle query
	// into four lookups instead of a loop over its pixels.
	prefix []float64
	cells  []float64
}

// NewInkMap builds a map from a row-major slice of densities.
func NewInkMap(width, height int, cells []float64) (InkMap, error) {
	if width <= 0 || height <= 0 {
		return InkMap{}, fmt.Errorf("ink map needs positive dimensions, got %dx%d", width, height)
	}
	if len(cells) != width*height {
		return InkMap{}, fmt.Errorf("ink map needs %d cells, got %d", width*height, len(cells))
	}

	for index, value := range cells {
		if value < 0 || value > 1 || math.IsNaN(value) {
			return InkMap{}, fmt.Errorf("ink density at %d is %v, expected 0..1", index, value)
		}
	}

	prefix := make([]float64, (width+1)*(height+1))
	for y := 0; y < height; y++ {
		rowSum := 0.0
		for x := 0; x < width; x++ {
			rowSum += cells[y*width+x]
			prefix[(y+1)*(width+1)+(x+1)] = prefix[y*(width+1)+(x+1)] + rowSum
		}
	}

	// The cells slice is copied so a caller cannot mutate the map behind us.
	snapshot := make([]float64, len(cells))
	copy(snapshot, cells)

	return InkMap{width: width, height: height, prefix: prefix, cells: snapshot}, nil
}

// Width returns the map width in cells.
func (m InkMap) Width() int { return m.width }

// Height returns the map height in cells.
func (m InkMap) Height() int { return m.height }

// Ink returns the density of one cell.
func (m InkMap) Ink(x, y int) float64 {
	if x < 0 || y < 0 || x >= m.width || y >= m.height {
		return 0
	}
	return m.cells[y*m.width+x]
}

// InkIn returns the average ink density inside a rectangle.
//
// The rectangle is clipped to the map, so callers may probe slightly outside
// the page without a bounds check of their own.
func (m InkMap) InkIn(x, y, width, height int) float64 {
	if width <= 0 || height <= 0 {
		return 0
	}

	x0, y0 := clamp(x, 0, m.width), clamp(y, 0, m.height)
	x1, y1 := clamp(x+width, 0, m.width), clamp(y+height, 0, m.height)
	if x1 <= x0 || y1 <= y0 {
		return 0
	}

	stride := m.width + 1
	total := m.prefix[y1*stride+x1] -
		m.prefix[y0*stride+x1] -
		m.prefix[y1*stride+x0] +
		m.prefix[y0*stride+x0]

	return total / float64((x1-x0)*(y1-y0))
}

// Candidate is a rectangle where a seal could sit, with its measured cost.
type Candidate struct {
	X      int
	Y      int
	Width  int
	Height int
	// Ink is the average ink inside the rectangle.
	Ink float64
	// SurroundingInk is the average ink of a margin around the rectangle, so a
	// box wedged against text scores worse than one in open space.
	SurroundingInk float64
	// Score is the ranking value: lower is better.
	Score float64
	// Zone names where on the page the rectangle sits, for the UI.
	Zone SealZone
}

// SealZone names a region of the page, used to rank candidates the way people
// actually place signatures.
type SealZone string

const (
	// ZoneBottomRight is the preferred place in Italian and Spanish practice.
	ZoneBottomRight SealZone = "bottom-right"

	// ZoneBottomLeft is used for second signatures and initials.
	ZoneBottomLeft SealZone = "bottom-left"

	// ZoneRightEdge suits long documents where the footer is full.
	ZoneRightEdge SealZone = "right-edge"

	// ZoneTopRight is acceptable when the page bottom is occupied.
	ZoneTopRight SealZone = "top-right"

	// ZoneElsewhere means no tidy region was found.
	ZoneElsewhere SealZone = "elsewhere"
)

// zoneWeights express the conventional preference order. Lower is better.
var zoneWeights = map[SealZone]float64{
	ZoneBottomRight: 0.0,
	ZoneBottomLeft:  0.15,
	ZoneRightEdge:   0.25,
	ZoneTopRight:    0.45,
	ZoneElsewhere:   0.60,
}

// FindFreeSpace returns up to limit rectangles of the requested size, emptiest
// and most conventional first.
//
// A safety margin keeps candidates away from the paper edge: printers clip a few
// millimetres, and a stamp half outside the printable area is worthless.
//
// The search is exhaustive over cell-aligned positions and cheap: one summed-area
// table query per position, so a 595x842 map costs about half a million
// constant-time lookups, which is a few milliseconds.
func (m InkMap) FindFreeSpace(sealWidth, sealHeight, limit int) ([]Candidate, error) {
	if sealWidth <= 0 || sealHeight <= 0 {
		return nil, fmt.Errorf("seal needs positive dimensions, got %dx%d", sealWidth, sealHeight)
	}
	if sealWidth > m.width || sealHeight > m.height {
		return nil, fmt.Errorf(
			"seal of %dx%d does not fit a page of %dx%d; reduce the box or the resolution",
			sealWidth, sealHeight, m.width, m.height,
		)
	}
	if limit <= 0 {
		limit = 3
	}

	// A margin of a fifth of the seal is enough to notice text right next to the
	// box without penalising a legitimate narrow footer.
	margin := max(4, min(sealWidth, sealHeight)/5)

	step := searchStep(sealWidth, sealHeight)
	// 2% of the page, or at least 6 cells, whichever is larger.
	marginCells := max(6, m.width/50)
	edgeX := min(marginCells, (m.width-sealWidth)/2)
	edgeY := min(marginCells, (m.height-sealHeight)/2)

	var candidates []Candidate
	for y := edgeY; y+sealHeight <= m.height-edgeY; y += step {
		for x := edgeX; x+sealWidth <= m.width-edgeX; x += step {
			ink := m.InkIn(x, y, sealWidth, sealHeight)
			if ink > coveringInk {
				// More ink than this inside the box means it covers text.
				continue
			}

			surrounding := m.InkIn(
				x-margin, y-margin,
				sealWidth+2*margin, sealHeight+2*margin,
			)

			zone := m.zoneFor(x, y, sealWidth, sealHeight)
			score := ink*2.0 + surrounding*1.5 + zoneWeights[zone]

			candidates = append(candidates, Candidate{
				X: x, Y: y, Width: sealWidth, Height: sealHeight,
				Ink: ink, SurroundingInk: surrounding,
				Score: score, Zone: zone,
			})
		}
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf(
			"no empty space of %dx%d px found: the page is too full, place the seal somewhere with --box",
			sealWidth, sealHeight,
		)
	}

	sortCandidates(candidates)

	// Return spread-out points rather than three neighbours two cells apart:
	// a user wants alternatives, not the same spot repeated.
	selected := make([]Candidate, 0, limit)
	minimumGap := max(sealWidth, sealHeight) / 2
	for _, candidate := range candidates {
		tooClose := false
		for _, chosen := range selected {
			if abs(candidate.X-chosen.X) < minimumGap && abs(candidate.Y-chosen.Y) < minimumGap {
				tooClose = true
				break
			}
		}
		if tooClose {
			continue
		}
		selected = append(selected, candidate)
		if len(selected) == limit {
			break
		}
	}
	return selected, nil
}

// zoneFor classifies a rectangle by its position on the page.
//
// The thresholds use thirds of the *usable* area, not of the raw page: the
// search keeps a safety margin from the paper edge, so measuring against the
// absolute edge would classify every legal candidate as "elsewhere".
func (m InkMap) zoneFor(x, y, width, height int) SealZone {
	thirdX := m.width / 3
	thirdY := m.height / 3

	// A candidate counts as bottom/right when it starts past the second third.
	bottom := y >= m.height-thirdY-thirdY/2
	right := x >= m.width-thirdX-thirdX/2
	left := x+width <= thirdX+thirdX/2
	top := y+height <= thirdY+thirdY/2

	switch {
	case bottom && right:
		return ZoneBottomRight
	case bottom && left:
		return ZoneBottomLeft
	case right:
		return ZoneRightEdge
	case top && right:
		return ZoneTopRight
	}
	return ZoneElsewhere
}

// searchStep keeps the exhaustive scan bounded: at most ~60 positions per axis,
// which is finer than the margin and still instant.
func searchStep(sealWidth, sealHeight int) int {
	return max(4, min(sealWidth, sealHeight)/6)
}

// sortCandidates orders by score with a deterministic tie-break, so the same
// page always yields the same suggestion.
func sortCandidates(candidates []Candidate) {
	for i := 1; i < len(candidates); i++ {
		current := candidates[i]
		j := i - 1
		for j >= 0 && lessCandidate(current, candidates[j]) {
			candidates[j+1] = candidates[j]
			j--
		}
		candidates[j+1] = current
	}
}

func lessCandidate(left, right Candidate) bool {
	if left.Score != right.Score {
		return left.Score < right.Score
	}
	// Prefer lower on the page, then further right: deterministic and matches
	// the convention the zone weights already encode.
	if left.Y != right.Y {
		return left.Y > right.Y
	}
	return left.X > right.X
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
