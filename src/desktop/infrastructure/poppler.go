//go:build gui

package infrastructure

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
)

// PopplerRenderer renders PDF pages with pdftoppm, which is present on every
// desktop that already opens PDFs.
//
// It draws the real page; without it trebaruna draws its own sketch
// (BuiltInRenderer).
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
	directory, err := os.MkdirTemp("", "trebaruna-preview-")
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

// compile-time check.
var _ application.DocumentRenderer = (*PopplerRenderer)(nil)
