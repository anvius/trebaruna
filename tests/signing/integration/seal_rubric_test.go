package integration_test

// The rubric in the seal (ADR-0012): to the left of the certificate data,
// its proportions kept, the data at the size they have without it, a box
// too narrow for both refused, and an image pdfsign would embed wrongly
// converted first. Checked by eye on pages rendered with pdftoppm.

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/domain/identity"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// rubricOf encodes a width x height picture: a transparent PNG, or a JPEG of
// the given colour model.
func rubricOf(t *testing.T, width, height int, format string) domain.Rubric {
	t.Helper()
	var buffer bytes.Buffer
	var err error
	switch format {
	case "png":
		picture := image.NewNRGBA(image.Rect(0, 0, width, height))
		picture.Set(width/2, height/2, color.NRGBA{20, 30, 90, 255})
		err = png.Encode(&buffer, picture)
	case "grey-jpeg":
		err = jpeg.Encode(&buffer, image.NewGray(image.Rect(0, 0, width, height)), nil)
	case "jpeg":
		err = jpeg.Encode(&buffer, image.NewRGBA(image.Rect(0, 0, width, height)), nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	rubric, err := domain.NewRubric(buffer.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return rubric
}

// drawnImage is the image element of an appearance.
type drawnImage struct {
	x, y, width, height float64
	data                []byte
}

// imagesIn reads the image elements of a seal.
func imagesIn(elements []any) []drawnImage {
	var found []drawnImage
	for _, element := range elements {
		value := reflect.ValueOf(element)
		if value.Kind() != reflect.Struct || !value.FieldByName("Image").IsValid() {
			continue
		}
		picture := value.FieldByName("Image").Elem()
		found = append(found, drawnImage{
			x: value.FieldByName("X").Float(), y: value.FieldByName("Y").Float(),
			width: value.FieldByName("Width").Float(), height: value.FieldByName("Height").Float(),
			data: picture.FieldByName("Data").Bytes(),
		})
	}
	return found
}

func sealElements(t *testing.T, width, height float64, rubric domain.Rubric) ([]any, []textLine) {
	t.Helper()
	holder := identity.Holder{Name: "MARIA LOPEZ GARCIA", Identifier: "IDCES-00000000X"}
	appearance, err := infrastructure.DrawSealWithRubric(width, height, holder, sampleMoment(), rubric)
	if err != nil {
		t.Fatalf("%vx%v: %v", width, height, err)
	}
	var elements []any
	for _, element := range appearance.RenderInfo().Elements {
		elements = append(elements, element)
	}
	return elements, textLines(appearance)
}

// TestARubricSitsLeftOfTheDataAtTheirSize.
func TestARubricSitsLeftOfTheDataAtTheirSize(t *testing.T) {
	elements, lines := sealElements(t, 160, 48, rubricOf(t, 300, 100, "png"))
	pictures := imagesIn(elements)
	if len(pictures) != 1 {
		t.Fatalf("%d images", len(pictures))
	}
	picture := pictures[0]
	if math.Abs(picture.width/picture.height-3) > 0.01 || picture.x+picture.width > 80 ||
		math.Abs(picture.y+picture.height/2-24) > 0.01 {
		t.Errorf("image at %+v: 3:1, within the left half, centred", picture)
	}
	_, alone := sealElements(t, 160, 48, domain.Rubric{})
	if len(lines) != len(alone) {
		t.Fatalf("%d lines beside the rubric, %d without", len(lines), len(alone))
	}
	for index, line := range lines {
		if line.x <= picture.x+picture.width {
			t.Errorf("%q at %.1f overlaps the rubric ending at %.1f", line.text, line.x, picture.x+picture.width)
		}
		if line.size != alone[index].size {
			t.Errorf("%q at %.2f pt beside the rubric, %.2f without", line.text, line.size, alone[index].size)
		}
	}
}

// TestATallRubricKeepsItsProportions: the height bounds it.
func TestATallRubricKeepsItsProportions(t *testing.T) {
	elements, _ := sealElements(t, 160, 48, rubricOf(t, 100, 200, "png"))
	picture := imagesIn(elements)[0]
	if math.Abs(picture.height-(48-2*2.6)) > 0.01 || math.Abs(picture.width*2-picture.height) > 0.01 {
		t.Errorf("tall rubric drawn %vx%v", picture.width, picture.height)
	}
}

// TestABoxTooNarrowForTheRubricAndTheDataIsRefused rather than shrinking
// the data.
func TestABoxTooNarrowForTheRubricAndTheDataIsRefused(t *testing.T) {
	holder := identity.Holder{Name: "MARIA LOPEZ GARCIA", Identifier: "IDCES-00000000X"}
	_, err := infrastructure.DrawSealWithRubric(48, 48, holder, sampleMoment(), rubricOf(t, 300, 100, "png"))
	if err == nil || !strings.Contains(err.Error(), "beside the rubric") {
		t.Errorf("a 48 pt seal with a rubric: %v", err)
	}
}

// TestAJPEGPdfsignWouldMisreadIsConverted: pdfsign copies a JPEG as
// /DeviceRGB, right for a colour one only; a greyscale one goes as PNG.
func TestAJPEGPdfsignWouldMisreadIsConverted(t *testing.T) {
	for format, signature := range map[string][]byte{"grey-jpeg": []byte("\x89PNG"), "jpeg": {0xFF, 0xD8}, "png": []byte("\x89PNG")} {
		elements, _ := sealElements(t, 160, 48, rubricOf(t, 60, 20, format))
		if data := imagesIn(elements)[0].data; !bytes.HasPrefix(data, signature) {
			t.Errorf("%s handed to pdfsign as % x…", format, data[:4])
		}
	}
}

// TestAPDFSignedWithARubricVerifies, the image and its transparency in it.
func TestAPDFSignedWithARubricVerifies(t *testing.T) {
	fixture := newFixture(t)
	original := mustRead(t, writeBlankPDF(t, fixture.directory))
	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content: original, Signer: xadesTestSigner(t), Level: domain.BES, SignedAt: time.Now(),
		Placements: []domain.SealPlacement{domain.DefaultSeal(1).WithRoomForRubric()},
		Rubric:     rubricOf(t, 300, 100, "png"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed, []byte("/Subtype /Image")) || !bytes.Contains(signed, []byte("/SMask")) {
		t.Error("the signed PDF holds no image with its transparency")
	}
	path := filepath.Join(fixture.directory, "signed.pdf")
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewPDFVerifier().Extract(path)
	if err != nil || len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood {
		t.Errorf("%+v %v", reports, err)
	}
}
