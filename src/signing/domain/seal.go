package domain

import "fmt"

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
	image       []byte
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
	const width, height, margin = 64.0, 48.0, 18.0
	return SealPlacement{
		page:        page,
		lowerLeftX:  a4Width - margin - width,
		lowerLeftY:  margin,
		upperRightX: a4Width - margin,
		upperRightY: margin + height,
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
