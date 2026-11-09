package domain_test

// The rubric (ADR-0012): a PNG or JPEG of bounded size, and a default seal
// widened for it so the certificate data keep their size.

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

func encoded(t *testing.T, width, height int, encode func(*bytes.Buffer, image.Image) error) []byte {
	t.Helper()
	picture := image.NewNRGBA(image.Rect(0, 0, width, height))
	picture.Set(1, 1, color.NRGBA{20, 30, 90, 255})
	var buffer bytes.Buffer
	if err := encode(&buffer, picture); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func asPNG(buffer *bytes.Buffer, picture image.Image) error { return png.Encode(buffer, picture) }
func asJPEG(buffer *bytes.Buffer, picture image.Image) error {
	return jpeg.Encode(buffer, picture, nil)
}
func asGIF(buffer *bytes.Buffer, picture image.Image) error { return gif.Encode(buffer, picture, nil) }

// TestARubricIsAPNGOrAJPEG, its proportions read from it.
func TestARubricIsAPNGOrAJPEG(t *testing.T) {
	for name, content := range map[string][]byte{"PNG": encoded(t, 300, 100, asPNG), "JPEG": encoded(t, 300, 100, asJPEG)} {
		rubric, err := domain.NewRubric(content)
		if err != nil || rubric.IsZero() || rubric.AspectRatio() != 3 || !bytes.Equal(rubric.Content(), content) {
			t.Errorf("%s: %v, aspect %v", name, err, rubric.AspectRatio())
		}
	}
	if !(domain.Rubric{}).IsZero() {
		t.Error("the zero rubric is no rubric")
	}
}

// TestWhatCannotBeARubricIsRefused: other formats, other files, images
// too large to decode safely.
func TestWhatCannotBeARubricIsRefused(t *testing.T) {
	for name, content := range map[string][]byte{
		"a GIF":            encoded(t, 30, 10, asGIF),
		"a PDF":            []byte("%PDF-1.7"),
		"nothing":          nil,
		"5000 pixels wide": encoded(t, 5000, 10, asPNG),
		"5 MiB":            append(encoded(t, 30, 10, asPNG), make([]byte, 5<<20)...),
	} {
		if _, err := domain.NewRubric(content); !errors.Is(err, domain.ErrRubric) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTheDefaultSealWidensForARubric, and a seal the signer placed keeps
// its box.
func TestTheDefaultSealWidensForARubric(t *testing.T) {
	corner := domain.DefaultSeal(2).WithRoomForRubric()
	if corner.Width() != 160 || corner.Height() != 48 || !corner.IsCorner() {
		t.Errorf("default seal with a rubric: %vx%v", corner.Width(), corner.Height())
	}
	placed := corner.OnPage(0, 0, 612, 792)
	if lowerLeftX, _, _, _ := placed.Box(); placed.Width() != 160 || lowerLeftX != 612-18-160 {
		t.Errorf("on a Letter page: width %v, lower left %v", placed.Width(), lowerLeftX)
	}
	box, _ := domain.PlaceSeal(1, 100, 100, 200, 150)
	if widened := box.WithRoomForRubric(); widened != box {
		t.Error("a placed seal changed its box")
	}
}
