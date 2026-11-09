package domain

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"io"
	"math"
	// The two formats a rubric may come in register their decoders.
	_ "image/jpeg"
	_ "image/png"
)

// Rubric is the image of a handwritten signature the seal shows beside the
// certificate data (ADR-0012): never alone, never in place of the data,
// which keep their size.
type Rubric struct {
	content       []byte
	width, height int
}

// Bounds of a rubric. A scanned signature is a few hundred pixels wide; the
// limits keep a crafted image from exhausting memory once it is decoded.
const (
	rubricMaxBytes = 4 << 20
	rubricMaxSide  = 4096
)

// ErrRubric means an image that cannot be a rubric.
var ErrRubric = errors.New("the rubric must be a PNG or JPEG image")

// NewRubric reads a rubric: a PNG or a JPEG, at most 4 MiB and 4096 pixels
// a side.
func NewRubric(content []byte) (Rubric, error) {
	if len(content) > rubricMaxBytes {
		return Rubric{}, fmt.Errorf("%w of at most %d MiB, not %d bytes", ErrRubric, rubricMaxBytes>>20, len(content))
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(content))
	if err != nil || (format != "png" && format != "jpeg") {
		return Rubric{}, ErrRubric
	}
	if config.Width < 1 || config.Height < 1 || config.Width > rubricMaxSide || config.Height > rubricMaxSide {
		return Rubric{}, fmt.Errorf("%w of at most %d pixels a side, not %dx%d", ErrRubric, rubricMaxSide, config.Width, config.Height)
	}
	return Rubric{content: content, width: config.Width, height: config.Height}, nil
}

// ReadRubric reads a rubric, refusing one too large before reading it
// whole.
func ReadRubric(reader io.Reader) (Rubric, error) {
	content, err := io.ReadAll(io.LimitReader(reader, rubricMaxBytes+1))
	if err != nil {
		return Rubric{}, err
	}
	return NewRubric(content)
}

// IsZero reports no rubric.
func (r Rubric) IsZero() bool { return len(r.content) == 0 }

// Content is the image as given.
func (r Rubric) Content() []byte { return r.content }

// AspectRatio is the image's width over its height.
func (r Rubric) AspectRatio() float64 { return float64(r.width) / float64(r.height) }

// rubricGap separates the rubric from the certificate data.
const rubricGap = 2.0

// Fit places the rubric in a seal width x height pt with the given inner
// padding (ADR-0012): at the left, vertically centred, as large as its
// proportions allow within the padding and half the width. dataLeft is
// where the certificate data start. ok is false when the seal has no room
// for it at all.
func (r Rubric) Fit(width, height, padding float64) (box SealRect, dataLeft float64, ok bool) {
	areaWidth, areaHeight := width/2-padding, height-2*padding
	if r.IsZero() || areaWidth <= 0 || areaHeight <= 0 {
		return SealRect{}, 0, false
	}
	imageHeight := math.Min(areaWidth/r.AspectRatio(), areaHeight)
	imageWidth := imageHeight * r.AspectRatio()
	box = SealRect{X: padding, Y: (height - imageHeight) / 2, Width: imageWidth, Height: imageHeight}
	return box, padding + imageWidth + rubricGap, true
}

// SealRect is a rectangle inside a seal, in points from its lower-left
// corner.
type SealRect struct{ X, Y, Width, Height float64 }
