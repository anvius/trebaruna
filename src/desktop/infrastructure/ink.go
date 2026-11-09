package infrastructure

// This file carries no build tag: both renderers measure ink with it.

import (
	"bytes"
	"fmt"
	"image"
	"image/png"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

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
