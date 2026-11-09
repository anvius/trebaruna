package domain

import (
	"fmt"
	"math"
)

// SealPlacement is where, and how, the visible signature appears on a page.
//
// It exists because "firmar visiblemente" is a business requirement: a
// signature that lands on top of text is a bug, not a cosmetic detail.
type SealPlacement struct {
	page        int
	lowerLeftX  float64
	lowerLeftY  float64
	upperRightX float64
	upperRightY float64
	// corner marks the default seal: its coordinates assume A4 until OnPage
	// places it on the real page.
	corner bool
	// wide is a default seal with room for a rubric beside the data.
	wide bool
}

// A4 in PDF user-space points (1 pt = 1/72 inch).
const (
	a4Width  = 595.28
	a4Height = 841.89
)

// PlaceSeal builds a placement from explicit page and box coordinates,
// expressed in PDF points with the origin at the bottom-left corner.
func PlaceSeal(page int, lx, ly, ux, uy float64) (SealPlacement, error) {
	if page < 1 {
		return SealPlacement{}, fmt.Errorf("seal page must be 1 or greater, got %d", page)
	}
	if ux <= lx {
		return SealPlacement{}, fmt.Errorf("seal box needs upperRightX > lowerLeftX, got %v <= %v", ux, lx)
	}
	if uy <= ly {
		return SealPlacement{}, fmt.Errorf("seal box needs upperRightY > lowerLeftY, got %v <= %v", uy, ly)
	}
	if lx < 0 || ly < 0 {
		return SealPlacement{}, fmt.Errorf("seal box cannot start at negative coordinates, got (%v,%v)", lx, ly)
	}
	return SealPlacement{
		page: page, lowerLeftX: lx, lowerLeftY: ly, upperRightX: ux, upperRightY: uy,
	}, nil
}

// DefaultSeal is a compact stamp in the bottom-right corner.
//
// 64x48 pt (about 23x17 mm) is a presentation choice that fits in the margin of
// a normal page. ETSI does not prescribe a seal size; it only requires that the
// appearance not obscure the signed content.
func DefaultSeal(page int) SealPlacement {
	return SealPlacement{
		page:        page,
		lowerLeftX:  a4Width - cornerMargin - cornerWidth,
		lowerLeftY:  cornerMargin,
		upperRightX: a4Width - cornerMargin,
		upperRightY: cornerMargin + cornerHeight,
		corner:      true,
	}
}

// The default seal: 64x48 pt, 18 pt from the bottom and right edges; 160 pt
// wide when it carries a rubric, so the certificate data keep the size they
// have without one (ADR-0012).
const (
	cornerWidth       = 64.0
	cornerRubricWidth = 160.0
	cornerHeight      = 48.0
	cornerMargin      = 18.0
)

// WithRoomForRubric widens the default seal for a rubric beside the
// certificate data. A seal the signer placed keeps its box: if the data do
// not fit beside the rubric there, signing is refused, never shrunk.
func (s SealPlacement) WithRoomForRubric() SealPlacement {
	if !s.corner {
		return s
	}
	s.wide = true
	s.lowerLeftX = a4Width - cornerMargin - cornerRubricWidth
	return s
}

// IsCorner reports the default seal, which still has to be placed on the page.
func (s SealPlacement) IsCorner() bool { return s.corner }

// OnPage places the default seal in the bottom-right corner of a page whose
// visible box spans left..right and bottom..top in PDF points. A page smaller
// than the seal and its margins gets the seal at its lower-left origin rather
// than at negative coordinates.
func (s SealPlacement) OnPage(left, bottom, right, top float64) SealPlacement {
	if !s.corner {
		return s
	}
	width := cornerWidth
	if s.wide {
		width = cornerRubricWidth
	}
	lowerLeftX := math.Max(left, right-cornerMargin-width)
	lowerLeftY := math.Min(bottom+cornerMargin, math.Max(bottom, top-cornerHeight))
	return SealPlacement{
		page:        s.page,
		lowerLeftX:  lowerLeftX,
		lowerLeftY:  lowerLeftY,
		upperRightX: lowerLeftX + width,
		upperRightY: lowerLeftY + cornerHeight,
	}
}

// Page is the 1-based page number.
func (s SealPlacement) Page() int { return s.page }

// Box returns the rectangle in PDF points.
func (s SealPlacement) Box() (lx, ly, ux, uy float64) {
	return s.lowerLeftX, s.lowerLeftY, s.upperRightX, s.upperRightY
}

// Width returns the seal width in points.
func (s SealPlacement) Width() float64 { return s.upperRightX - s.lowerLeftX }

// Height returns the seal height in points.
func (s SealPlacement) Height() float64 { return s.upperRightY - s.lowerLeftY }

// IsZero reports whether the placement carries no explicit geometry.
func (s SealPlacement) IsZero() bool {
	return s.page == 0 && s.upperRightX == 0 && s.upperRightY == 0
}
