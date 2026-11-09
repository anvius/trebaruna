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

// The smallest seal the window lets a user draw. It is the default stamp: the
// signer scales the type to the box, and below this the certificate identity
// no longer fits without truncation, which the signer refuses.
const (
	MinimumSealWidth  = 64.0
	MinimumSealHeight = 48.0
)

// coveringInk is the average density above which a box is said to sit on top
// of text. It is the same threshold the free-space search rejects.
const coveringInk = 0.08

// Covers reports whether the seal would sit on top of printed content.
func (g PageGeometry) Covers(ink InkMap, rect SealRect) bool {
	cell := g.ToCandidate(rect)
	return ink.InkIn(cell.X, cell.Y, cell.Width, cell.Height) > coveringInk
}

// Contains reports whether a point lies inside the rectangle, edges included.
func (r Rectangle) Contains(x, y float64) bool {
	return x >= r.X && y >= r.Y && x <= r.X+r.Width && y <= r.Y+r.Height
}

// DisplayFit is how a page is drawn inside a frame on screen: scaled to fit
// whole, and centred along the axis that has room to spare.
//
// Every pointer event goes through it. Drawing the page with one scale and
// reading the pointer with another is what made the old overlay drift away
// from the cursor, so both directions live here and are tested together.
type DisplayFit struct {
	// Scale is screen units per PDF point.
	Scale   float64
	OffsetX float64
	OffsetY float64
	page    PageGeometry
}

// FitInto computes the fit of the page inside a frame of the given size.
func (g PageGeometry) FitInto(frameWidth, frameHeight float64) DisplayFit {
	if frameWidth <= 0 || frameHeight <= 0 {
		return DisplayFit{page: g}
	}
	scale := math.Min(frameWidth/g.WidthPoints, frameHeight/g.HeightPoints)
	return DisplayFit{
		Scale:   scale,
		OffsetX: (frameWidth - g.WidthPoints*scale) / 2,
		OffsetY: (frameHeight - g.HeightPoints*scale) / 2,
		page:    g,
	}
}

// PageArea is the rectangle the page occupies on screen.
func (f DisplayFit) PageArea() Rectangle {
	return Rectangle{
		X: f.OffsetX, Y: f.OffsetY,
		Width: f.page.WidthPoints * f.Scale, Height: f.page.HeightPoints * f.Scale,
	}
}

// ToScreen converts a seal into screen units with a top-left origin.
func (f DisplayFit) ToScreen(rect SealRect) Rectangle {
	return Rectangle{
		X:      f.OffsetX + rect.LowerLeftX*f.Scale,
		Y:      f.OffsetY + (f.page.HeightPoints-rect.UpperRightY)*f.Scale,
		Width:  rect.Width() * f.Scale,
		Height: rect.Height() * f.Scale,
	}
}

// ToPage converts a screen point into PDF points. Inside is false when the
// point falls on the frame around the page rather than on the paper.
func (f DisplayFit) ToPage(x, y float64) (pointX, pointY float64, inside bool) {
	if f.Scale <= 0 {
		return 0, 0, false
	}
	pointX = (x - f.OffsetX) / f.Scale
	pointY = f.page.HeightPoints - (y-f.OffsetY)/f.Scale
	inside = pointX >= 0 && pointY >= 0 && pointX <= f.page.WidthPoints && pointY <= f.page.HeightPoints
	return pointX, pointY, inside
}

// CentredAt places a seal of the given size with its centre under a screen
// point, kept whole on the page. This is what a click on the page does.
func (f DisplayFit) CentredAt(x, y, width, height float64) SealRect {
	pointX, pointY, _ := f.ToPage(x, y)
	return f.page.Clamp(SealRect{
		LowerLeftX:  pointX - width/2,
		LowerLeftY:  pointY - height/2,
		UpperRightX: pointX + width/2,
		UpperRightY: pointY + height/2,
	})
}

// Move translates a seal by a screen-space delta and keeps it on the page.
//
// Screen Y grows downwards and PDF Y grows upwards, so the vertical delta is
// inverted; without that the seal runs away from the pointer.
func (f DisplayFit) Move(rect SealRect, deltaX, deltaY float64) SealRect {
	if f.Scale <= 0 {
		return rect
	}
	return f.page.Clamp(rect.MoveBy(deltaX/f.Scale, -deltaY/f.Scale))
}

// Grow resizes a seal from its bottom-right corner on screen, which is where
// the handle sits: the top-left corner stays put, and the seal never shrinks
// below the minimum or grows past the page edge.
func (f DisplayFit) Grow(rect SealRect, deltaX, deltaY float64) SealRect {
	if f.Scale <= 0 {
		return rect
	}
	width := math.Max(MinimumSealWidth, rect.Width()+deltaX/f.Scale)
	height := math.Max(MinimumSealHeight, rect.Height()+deltaY/f.Scale)
	width = math.Min(width, f.page.WidthPoints-rect.LowerLeftX)
	height = math.Min(height, rect.UpperRightY)

	return SealRect{
		LowerLeftX:  rect.LowerLeftX,
		LowerLeftY:  rect.UpperRightY - height,
		UpperRightX: rect.LowerLeftX + width,
		UpperRightY: rect.UpperRightY,
	}
}
