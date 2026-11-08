package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// PagePreview is a rendered page plus the ink measurement of that render.
type PagePreview struct {
	// PageNumber is 1-based.
	PageNumber int
	// WidthPoints and HeightPoints are the PDF page size.
	WidthPoints  float64
	HeightPoints float64
	// PNG is the rendered page, ready to display.
	PNG []byte
	// RasterWidth and RasterHeight are the ink map dimensions, which may be a
	// downscaled version of the PNG.
	RasterWidth  int
	RasterHeight int
	// Ink lets the use case find empty space without touching pixels.
	Ink domain.InkMap
	// PageCount is the total number of pages in the document.
	PageCount int
}

// Geometry exposes the conversion between raster cells and PDF points.
func (p PagePreview) Geometry() (domain.PageGeometry, error) {
	return domain.NewPageGeometry(p.WidthPoints, p.HeightPoints, p.RasterWidth, p.RasterHeight)
}

// DocumentRenderer turns a PDF into previewable pages.
//
// The interface exists so the window never shells out to a binary itself, and so
// tests can supply a synthetic document without poppler.
type DocumentRenderer interface {
	// RenderPage renders one page and measures its ink.
	RenderPage(ctx context.Context, documentPath string, page int) (PagePreview, error)
}

// FreeSpaceFinder suggests seal positions on a rendered page.
type FreeSpaceFinder interface {
	Suggest(ink domain.InkMap, sealWidth, sealHeight, limit int) ([]domain.Candidate, error)
}
