//go:build gui

package infrastructure

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"codeberg.org/simplicer/firma-it/src/desktop/application"
	"codeberg.org/simplicer/firma-it/src/desktop/domain"
)

// ErrRendererMissing reports that poppler is not installed.
//
// Preview needs an external rasteriser; signing does not. The distinction
// matters on a clean machine (and on macOS, which ships no poppler): a missing
// preview must degrade to manual placement, never block the signature.
var ErrRendererMissing = errors.New("no PDF renderer available")

// PopplerRenderer renders PDF pages with pdftoppm, which is present on every
// desktop that already opens PDFs.
//
// Rendering in-process would mean shipping a PDF rasteriser; poppler is the one
// the system already uses, and shelling out to it costs a few milliseconds.
type PopplerRenderer struct {
	// Resolution is the DPI used for the preview.
	Resolution int
	// RasterMaxWidth caps the ink map width. Measuring ink needs far less
	// resolution than displaying the page.
	RasterMaxWidth int
	// findPoppler allows tests to inject a fake binary.
	findPoppler func(string) (string, error)
}

// NewPopplerRenderer builds the renderer with sensible defaults.
func NewPopplerRenderer() *PopplerRenderer {
	return &PopplerRenderer{
		Resolution:     110,
		RasterMaxWidth: 300,
		findPoppler:    exec.LookPath,
	}
}

// RenderPage rasterises one page and computes its ink map.
func (r *PopplerRenderer) RenderPage(ctx context.Context, documentPath string, page int) (application.PagePreview, error) {
	if page < 1 {
		return application.PagePreview{}, fmt.Errorf("page numbers start at 1, got %d", page)
	}

	binary, err := r.findPoppler("pdftoppm")
	if err != nil {
		return application.PagePreview{}, fmt.Errorf("%w: pdftoppm is not installed", ErrRendererMissing)
	}

	pageCount, widthPoints, heightPoints, err := readPageInfo(ctx, documentPath)
	if err != nil {
		return application.PagePreview{}, err
	}
	if page > pageCount {
		return application.PagePreview{}, fmt.Errorf(
			"the document has %d pages, cannot preview page %d", pageCount, page,
		)
	}

	pngBytes, err := rasterise(ctx, binary, documentPath, page, r.Resolution)
	if err != nil {
		return application.PagePreview{}, err
	}

	ink, rasterWidth, rasterHeight, err := measureInk(pngBytes, r.RasterMaxWidth)
	if err != nil {
		return application.PagePreview{}, err
	}

	return application.PagePreview{
		PageNumber:   page,
		WidthPoints:  widthPoints,
		HeightPoints: heightPoints,
		PNG:          pngBytes,
		RasterWidth:  rasterWidth,
		RasterHeight: rasterHeight,
		Ink:          ink,
		PageCount:    pageCount,
	}, nil
}

// readPageInfo asks pdfinfo for the page count and the first page geometry.
func readPageInfo(ctx context.Context, documentPath string) (pageCount int, width, height float64, err error) {
	binary, lookErr := exec.LookPath("pdfinfo")
	if lookErr != nil {
		return 0, 0, 0, fmt.Errorf("%w: pdfinfo is not installed", ErrRendererMissing)
	}

	command := exec.CommandContext(ctx, binary, documentPath)
	output, runErr := command.Output()
	if runErr != nil {
		return 0, 0, 0, fmt.Errorf("pdfinfo failed on %s: %w", documentPath, runErr)
	}

	pagePattern := regexp.MustCompile(`(?m)^Pages:\s+(\d+)`)
	sizePattern := regexp.MustCompile(`(?m)^Page size:\s+([\d.]+) x ([\d.]+)`)

	pageMatch := pagePattern.FindStringSubmatch(string(output))
	sizeMatch := sizePattern.FindStringSubmatch(string(output))
	if pageMatch == nil || sizeMatch == nil {
		return 0, 0, 0, fmt.Errorf("cannot read page geometry from %s", documentPath)
	}

	pageCount, _ = strconv.Atoi(pageMatch[1])
	width, _ = strconv.ParseFloat(sizeMatch[1], 64)
	height, _ = strconv.ParseFloat(sizeMatch[2], 64)
	return pageCount, width, height, nil
}

// rasterise calls pdftoppm for a single page and returns the PNG bytes.
func rasterise(ctx context.Context, binary, documentPath string, page, resolution int) ([]byte, error) {
	directory, err := os.MkdirTemp("", "firma-it-preview-")
	if err != nil {
		return nil, fmt.Errorf("create preview directory: %w", err)
	}
	defer os.RemoveAll(directory)

	prefix := filepath.Join(directory, "page")
	command := exec.CommandContext(ctx, binary,
		"-png", "-r", strconv.Itoa(resolution),
		"-f", strconv.Itoa(page), "-l", strconv.Itoa(page),
		documentPath, prefix,
	)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		return nil, fmt.Errorf("pdftoppm failed: %w\n%s", runErr, strings.TrimSpace(string(output)))
	}

	rendered, err := filepath.Glob(prefix + "-*.png")
	if err != nil || len(rendered) == 0 {
		return nil, fmt.Errorf("pdftoppm produced no page image")
	}

	content, err := os.ReadFile(rendered[0])
	if err != nil {
		return nil, fmt.Errorf("read rendered page: %w", err)
	}
	return content, nil
}

// measureInk converts the PNG into an ink density map.
//
// Ink is derived from luminance rather than alpha: a rendered PDF page is
// always opaque, so darkness is the only signal that something is printed
// there. The map is downscaled to a fixed width because a 110 DPI page yields
// roughly a million cells, far more than the free-space search needs.
func measureInk(pngBytes []byte, maxWidth int) (domain.InkMap, int, int, error) {
	decoded, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return domain.InkMap{}, 0, 0, fmt.Errorf("decode rendered page: %w", err)
	}

	bounds := decoded.Bounds()
	sourceWidth, sourceHeight := bounds.Dx(), bounds.Dy()
	if sourceWidth == 0 || sourceHeight == 0 {
		return domain.InkMap{}, 0, 0, fmt.Errorf("rendered page is empty")
	}

	if maxWidth <= 0 {
		maxWidth = 300
	}
	width := sourceWidth
	if width > maxWidth {
		width = maxWidth
	}
	height := int(float64(sourceHeight) * float64(width) / float64(sourceWidth))
	if height < 1 {
		height = 1
	}

	cells := make([]float64, width*height)
	xScale := float64(sourceWidth) / float64(width)
	yScale := float64(sourceHeight) / float64(height)

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			// Sample the cell centre, averaging the four corners of the source
			// block so a thin line is not missed between samples.
			total := 0.0
			samples := 0
			for _, offsetY := range []float64{0.25, 0.75} {
				for _, offsetX := range []float64{0.25, 0.75} {
					sampleX := int((float64(x) + offsetX) * xScale)
					sampleY := int((float64(y) + offsetY) * yScale)
					if sampleX >= sourceWidth {
						sampleX = sourceWidth - 1
					}
					if sampleY >= sourceHeight {
						sampleY = sourceHeight - 1
					}
					total += darkness(decoded, bounds.Min.X+sampleX, bounds.Min.Y+sampleY)
					samples++
				}
			}
			cells[y*width+x] = total / float64(samples)
		}
	}

	ink, err := domain.NewInkMap(width, height, cells)
	if err != nil {
		return domain.InkMap{}, 0, 0, err
	}
	return ink, width, height, nil
}

// darkness converts a pixel into 0 (white) .. 1 (black).
func darkness(source image.Image, x, y int) float64 {
	red, green, blue, alpha := source.At(x, y).RGBA()

	// Composite over white: a transparent pixel is blank paper, not black.
	alphaFraction := float64(alpha) / 65535.0
	luminance := (0.299*float64(red) + 0.587*float64(green) + 0.114*float64(blue)) / 65535.0
	composited := luminance*alphaFraction + (1 - alphaFraction)

	return 1.0 - composited
}

// compile-time check.
var _ application.DocumentRenderer = (*PopplerRenderer)(nil)
