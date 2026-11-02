package domain

import (
	"fmt"
	"math"
)

// PageGeometry ties three coordinate systems together so a drag in the window
// becomes the right rectangle in the PDF.
//
// The three are: PDF points (what the signature needs), raster cells (what the
// ink map uses), and screen pixels (what the user drags). Converting between
// them in one place is what keeps the seal where the user dropped it.
type PageGeometry struct {
	// WidthPoints and HeightPoints are the PDF page size in points.
	WidthPoints  float64
	HeightPoints float64
	// RasterWidth and RasterHeight are the ink map dimensions in cells.
	RasterWidth  int
	RasterHeight int
}

// NewPageGeometry validates the page and raster sizes.
func NewPageGeometry(widthPoints, heightPoints float64, rasterWidth, rasterHeight int) (PageGeometry, error) {
	if widthPoints <= 0 || heightPoints <= 0 {
		return PageGeometry{}, fmt.Errorf("page needs positive point dimensions, got %vx%v", widthPoints, heightPoints)
	}
	if rasterWidth <= 0 || rasterHeight <= 0 {
		return PageGeometry{}, fmt.Errorf("raster needs positive dimensions, got %dx%d", rasterWidth, rasterHeight)
	}
	return PageGeometry{
		WidthPoints:  widthPoints,
		HeightPoints: heightPoints,
		RasterWidth:  rasterWidth,
		RasterHeight: rasterHeight,
	}, nil
}

// PointsPerCellX is the horizontal scale from cells to points.
func (g PageGeometry) PointsPerCellX() float64 {
	return g.WidthPoints / float64(g.RasterWidth)
}

// PointsPerCellY is the vertical scale from cells to points.
func (g PageGeometry) PointsPerCellY() float64 {
	return g.HeightPoints / float64(g.RasterHeight)
}

// CellsPerPointX is the horizontal scale from points to cells.
func (g PageGeometry) CellsPerPointX() float64 {
	return float64(g.RasterWidth) / g.WidthPoints
}

// CellsPerPointY is the vertical scale from points to cells.
func (g PageGeometry) CellsPerPointY() float64 {
	return float64(g.RasterHeight) / g.HeightPoints
}

// Rectangle is a box in one coordinate system.
type Rectangle struct {
	X      float64
	Y      float64
	Width  float64
	Height float64
}

// CandidateRect converts a raster candidate into PDF points.
//
// Rasters are read top-down and PDFs are measured bottom-up, so the Y axis is
// flipped here. Getting that wrong puts every seal upside down on the page,
// which is the single most common bug in this conversion.
func (g PageGeometry) CandidateRect(candidate Candidate) Rectangle {
	widthPoints := float64(candidate.Width) * g.PointsPerCellX()
	heightPoints := float64(candidate.Height) * g.PointsPerCellY()

	return Rectangle{
		X:      float64(candidate.X) * g.PointsPerCellX(),
		Y:      g.HeightPoints - float64(candidate.Y+candidate.Height)*g.PointsPerCellY(),
		Width:  widthPoints,
		Height: heightPoints,
	}
}

// SealRect is a seal box in PDF points, ready for the CLI --box flag.
type SealRect struct {
	LowerLeftX  float64
	LowerLeftY  float64
	UpperRightX float64
	UpperRightY float64
}

// Clamp constrains a rectangle to the page, keeping its size when possible.
//
// A seal dragged past the edge comes back inside instead of being silently
// written at invalid coordinates.
func (g PageGeometry) Clamp(rect SealRect) SealRect {
	width := rect.UpperRightX - rect.LowerLeftX
	height := rect.UpperRightY - rect.LowerLeftY

	if width > g.WidthPoints {
		width = g.WidthPoints
	}
	if height > g.HeightPoints {
		height = g.HeightPoints
	}

	lowerLeftX := math.Max(0, math.Min(rect.LowerLeftX, g.WidthPoints-width))
	lowerLeftY := math.Max(0, math.Min(rect.LowerLeftY, g.HeightPoints-height))

	return SealRect{
		LowerLeftX:  lowerLeftX,
		LowerLeftY:  lowerLeftY,
		UpperRightX: lowerLeftX + width,
		UpperRightY: lowerLeftY + height,
	}
}

// FromCandidate builds a clamped seal rectangle from a raster candidate.
func (g PageGeometry) FromCandidate(candidate Candidate) SealRect {
	rectangle := g.CandidateRect(candidate)
	return g.Clamp(SealRect{
		LowerLeftX:  rectangle.X,
		LowerLeftY:  rectangle.Y,
		UpperRightX: rectangle.X + rectangle.Width,
		UpperRightY: rectangle.Y + rectangle.Height,
	})
}

// ToCandidates converts a seal rectangle back into a raster position, so the
// window can draw the overlay on top of the rendered page.
func (g PageGeometry) ToCandidate(rect SealRect) Candidate {
	x := int(rect.LowerLeftX * g.CellsPerPointX())
	width := int((rect.UpperRightX - rect.LowerLeftX) * g.CellsPerPointX())
	height := int((rect.UpperRightY - rect.LowerLeftY) * g.CellsPerPointY())
	y := int((g.HeightPoints - rect.UpperRightY) * g.CellsPerPointY())

	return Candidate{X: x, Y: y, Width: width, Height: height}
}

// Valid reports whether the rectangle has a real area inside the page.
func (g PageGeometry) Valid(rect SealRect) bool {
	if rect.UpperRightX <= rect.LowerLeftX || rect.UpperRightY <= rect.LowerLeftY {
		return false
	}
	if rect.LowerLeftX < 0 || rect.LowerLeftY < 0 {
		return false
	}
	if rect.UpperRightX > g.WidthPoints+0.01 || rect.UpperRightY > g.HeightPoints+0.01 {
		return false
	}
	return true
}

// BoxString renders the rectangle in the CLI syntax.
func (rect SealRect) BoxString() string {
	return fmt.Sprintf("%.1f,%.1f,%.1f,%.1f",
		rect.LowerLeftX, rect.LowerLeftY, rect.UpperRightX, rect.UpperRightY)
}

// MoveBy translates the rectangle, for drag operations.
func (rect SealRect) MoveBy(deltaX, deltaY float64) SealRect {
	return SealRect{
		LowerLeftX:  rect.LowerLeftX + deltaX,
		LowerLeftY:  rect.LowerLeftY + deltaY,
		UpperRightX: rect.UpperRightX + deltaX,
		UpperRightY: rect.UpperRightY + deltaY,
	}
}

// Resize changes the size while keeping the lower-left corner.
func (rect SealRect) Resize(width, height float64) SealRect {
	return SealRect{
		LowerLeftX:  rect.LowerLeftX,
		LowerLeftY:  rect.LowerLeftY,
		UpperRightX: rect.LowerLeftX + width,
		UpperRightY: rect.LowerLeftY + height,
	}
}

// Width is the rectangle width in points.
func (rect SealRect) Width() float64 { return rect.UpperRightX - rect.LowerLeftX }

// Height is the rectangle height in points.
func (rect SealRect) Height() float64 { return rect.UpperRightY - rect.LowerLeftY }
