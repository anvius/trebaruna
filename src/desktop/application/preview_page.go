package application

import (
	"context"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// PreviewPage produces a preview and suggests where the seal should go.
//
// It is the use case behind "abro el PDF y me propones dónde firmar": render,
// measure, search, and hand back both the image and ready-to-use rectangles.
type PreviewPage struct {
	renderer DocumentRenderer
	finder   FreeSpaceFinder
}

// NewPreviewPage wires the use case.
func NewPreviewPage(renderer DocumentRenderer, finder FreeSpaceFinder) *PreviewPage {
	return &PreviewPage{renderer: renderer, finder: finder}
}

// PreviewResult is what the window needs to draw the page and the seal.
type PreviewResult struct {
	Preview     PagePreview
	Geometry    domain.PageGeometry
	Suggestions []domain.Candidate
	SealRect    domain.SealRect
	SealSize    SealSize
}

// SealSize is the seal dimensions in PDF points.
type SealSize struct {
	Width  float64
	Height float64
}

// RubricSealSize matches the signer's default seal with a rubric beside the
// certificate data: 160x48 pt.
func RubricSealSize() SealSize {
	return SealSize{Width: 160, Height: 48}
}

// DefaultSealSize matches the compact stamp drawn by the signer: 64x48 pt.
func DefaultSealSize() SealSize {
	return SealSize{Width: 64, Height: 48}
}

// Execute renders the page and finds free space for the seal.
func (u *PreviewPage) Execute(ctx context.Context, documentPath string, page int, size SealSize) (PreviewResult, error) {
	preview, err := u.renderer.RenderPage(ctx, documentPath, page)
	if err != nil {
		return PreviewResult{}, err
	}

	geometry, err := preview.Geometry()
	if err != nil {
		return PreviewResult{}, err
	}

	if size.Width <= 0 || size.Height <= 0 {
		size = DefaultSealSize()
	}

	// Translate the point size into cells: the search works on the ink map.
	sealWidth := int(size.Width * geometry.CellsPerPointX())
	sealHeight := int(size.Height * geometry.CellsPerPointY())
	if sealWidth < 4 || sealHeight < 4 {
		return PreviewResult{}, fmt.Errorf(
			"the seal is too small to place: %vx%v pt maps to %dx%d cells",
			size.Width, size.Height, sealWidth, sealHeight,
		)
	}

	candidates, err := u.finder.Suggest(preview.Ink, sealWidth, sealHeight, 3)
	if err != nil {
		return PreviewResult{}, err
	}

	rect := geometry.FromCandidate(candidates[0])
	for _, candidate := range candidates {
		converted := geometry.FromCandidate(candidate)
		if geometry.Valid(converted) {
			rect = converted
			break
		}
	}

	return PreviewResult{
		Preview:     preview,
		Geometry:    geometry,
		Suggestions: candidates,
		SealRect:    rect,
		SealSize:    size,
	}, nil
}

// Suggest returns alternative placements without rendering again.
func (u *PreviewPage) Suggest(result PreviewResult, size SealSize) ([]domain.SealRect, error) {
	sealWidth := int(size.Width * result.Geometry.CellsPerPointX())
	sealHeight := int(size.Height * result.Geometry.CellsPerPointY())

	candidates, err := u.finder.Suggest(result.Preview.Ink, sealWidth, sealHeight, 6)
	if err != nil {
		return nil, err
	}

	rects := make([]domain.SealRect, 0, len(candidates))
	for _, candidate := range candidates {
		converted := result.Geometry.FromCandidate(candidate)
		if result.Geometry.Valid(converted) {
			rects = append(rects, converted)
		}
	}
	return rects, nil
}

// InkFinder is the production FreeSpaceFinder: it delegates to the domain rule.
type InkFinder struct{}

// Suggest finds empty rectangles on the page.
func (InkFinder) Suggest(ink domain.InkMap, sealWidth, sealHeight, limit int) ([]domain.Candidate, error) {
	return ink.FindFreeSpace(sealWidth, sealHeight, limit)
}

// compile-time check.
var _ FreeSpaceFinder = InkFinder{}
