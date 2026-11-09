package infrastructure_test

// The built-in renderer against a PDF whose every mark is known: text, a
// filled rectangle, a JPEG and a Flate picture, invisible OCR text, a form,
// an earlier signature's appearance, and a composite font read through its
// ToUnicode map. Real documents were also compared by eye with pdftoppm.

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"
)

// stream is a PDF stream object.
func stream(dictionary string, data []byte) string {
	return fmt.Sprintf("<< %s /Length %d >>\nstream\n%s\nendstream", dictionary, len(data), data)
}

// knownPDF writes a one-page A4 PDF with marks at known places.
func knownPDF(t *testing.T) string {
	t.Helper()
	var picture bytes.Buffer
	red := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for index := 0; index < len(red.Pix); index += 4 {
		red.Pix[index], red.Pix[index+3] = 230, 255
	}
	if err := jpeg.Encode(&picture, red, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	var blue bytes.Buffer
	writer := zlib.NewWriter(&blue)
	writer.Write(bytes.Repeat([]byte{0, 0, 220}, 16*16))
	writer.Close()

	content := strings.Join([]string{
		"BT /F1 40 Tf 100 700 Td (WWWW) Tj ET",
		"0 0 0 rg 300 100 100 50 re f",
		"q 100 0 0 100 100 300 cm /Im1 Do Q",
		"q 100 0 0 100 300 300 cm /Im2 Do Q",
		"BT 3 Tr /F1 40 Tf 100 550 Td (HIDDEN) Tj ET",
		"q 1 0 0 1 100 150 cm /Fm1 Do Q",
		"BT 0 Tr /F2 40 Tf 300 550 Td <00010001> Tj ET",
	}, "\n")
	toUnicode := "/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n" +
		"1 beginbfchar <0001> <0057> endbfchar\nendcmap CMapName currentdict /CMap defineresource pop end end"
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>",
		"<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [10 0 R] /Resources << /Font << /F1 5 0 R /F2 11 0 R >> " +
			"/XObject << /Im1 6 0 R /Im2 7 0 R /Fm1 8 0 R >> >> >>",
		stream("", []byte(content)),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
		stream("/Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode", picture.Bytes()),
		stream("/Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode", blue.Bytes()),
		stream("/Type /XObject /Subtype /Form /BBox [0 0 60 60]", []byte("0 0.6 0 rg 0 0 60 60 re f")),
		stream("/Type /XObject /Subtype /Form /BBox [0 0 100 50]", []byte("0.5 0 0.5 rg 0 0 100 50 re f")),
		"<< /Type /Annot /Subtype /Widget /Rect [450 700 550 750] /AP << /N 9 0 R >> >>",
		"<< /Type /Font /Subtype /Type0 /BaseFont /Sans-Bold /Encoding /Identity-H /DescendantFonts [12 0 R] /ToUnicode 13 0 R >>",
		"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Sans-Bold /DW 900 >>",
		stream("", []byte(toUnicode)),
	}
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for index, object := range objects {
		offsets[index] = pdf.Len()
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", index+1, object)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	path := filepath.Join(t.TempDir(), "known.pdf")
	if err := os.WriteFile(path, pdf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// at reads the rendered colour at a point of the page, in PDF points.
func at(t *testing.T, page image.Image, x, y float64) color.RGBA {
	t.Helper()
	scale := 110.0 / 72
	r, g, b, _ := page.At(int(x*scale), int((842-y)*scale)).RGBA()
	return color.RGBA{uint8(r >> 8), uint8(g >> 8), uint8(b >> 8), 255}
}

// inkAround reports whether any pixel in a box of the page is darker than
// paper.
func inkAround(page image.Image, x0, y0, x1, y1 float64) bool {
	scale := 110.0 / 72
	for y := int((842 - y1) * scale); y <= int((842-y0)*scale); y++ {
		for x := int(x0 * scale); x <= int(x1*scale); x++ {
			if r, _, _, _ := page.At(x, y).RGBA(); r < 0xA000 {
				return true
			}
		}
	}
	return false
}

func TestTheBuiltInRendererDrawsWhatThePageHolds(t *testing.T) {
	preview, err := infrastructure.NewBuiltInRenderer().RenderPage(context.Background(), knownPDF(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	if preview.PageCount != 1 || preview.WidthPoints != 595 || preview.HeightPoints != 842 || !preview.Approximate {
		t.Fatalf("%+v", preview)
	}
	page, err := png.Decode(bytes.NewReader(preview.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]bool{
		"the text":                           inkAround(page, 100, 700, 200, 730),
		"the rectangle":                      at(t, page, 350, 125) == color.RGBA{0, 0, 0, 255},
		"the JPEG":                           at(t, page, 150, 350).R > 200 && at(t, page, 150, 350).G < 60,
		"the Flate picture":                  at(t, page, 350, 350).B > 200 && at(t, page, 350, 350).R < 30,
		"the form":                           at(t, page, 130, 180).G > 120 && at(t, page, 130, 180).R < 30,
		"the earlier signature's appearance": at(t, page, 500, 725).R > 100 && at(t, page, 500, 725).G < 30,
		// A W reaches the cap height, which a stand-in bullet does not.
		"the composite font's text, read through ToUnicode": inkAround(page, 300, 574, 380, 578),
		"no invisible OCR text":                             !inkAround(page, 100, 550, 280, 580),
		"blank paper elsewhere":                             !inkAround(page, 450, 450, 550, 520),
	} {
		if !check {
			t.Errorf("%s is not drawn as it should be", name)
		}
	}
	if preview.Ink.InkIn(0, 0, preview.Ink.Width(), preview.Ink.Height()) == 0 {
		t.Error("the ink map is empty")
	}
}

func TestTheBuiltInRendererRefusesAPageTheDocumentLacks(t *testing.T) {
	if _, err := infrastructure.NewBuiltInRenderer().RenderPage(context.Background(), knownPDF(t), 2); err == nil {
		t.Error("page 2 of a one-page document")
	}
	if _, err := infrastructure.NewBuiltInRenderer().RenderPage(context.Background(), filepath.Join(t.TempDir(), "none.pdf"), 1); err == nil {
		t.Error("a missing file")
	}
}

// scriptedRenderer answers with a fixed result.
type scriptedRenderer struct {
	preview application.PagePreview
	err     error
	calls   *int
}

func (r scriptedRenderer) RenderPage(context.Context, string, int) (application.PagePreview, error) {
	*r.calls++
	return r.preview, r.err
}

// TestTheFirstInstalledRendererDraws: poppler missing hands over to the
// sketch; any other failure is the answer.
func TestTheFirstInstalledRendererDraws(t *testing.T) {
	calls := 0
	missing := scriptedRenderer{err: fmt.Errorf("%w: pdftoppm", infrastructure.ErrRendererMissing), calls: &calls}
	sketch := scriptedRenderer{preview: application.PagePreview{PageCount: 3, Approximate: true}, calls: &calls}
	if preview, err := (infrastructure.FirstAvailableRenderer{missing, sketch}).RenderPage(context.Background(), "a.pdf", 1); err != nil || preview.PageCount != 3 {
		t.Errorf("%+v %v", preview, err)
	}
	broken := scriptedRenderer{err: errors.New("damaged file"), calls: &calls}
	if _, err := (infrastructure.FirstAvailableRenderer{broken, sketch}).RenderPage(context.Background(), "a.pdf", 1); err == nil || err.Error() != "damaged file" {
		t.Errorf("a damaged file: %v", err)
	}
	if _, err := (infrastructure.FirstAvailableRenderer{missing}).RenderPage(context.Background(), "a.pdf", 1); !errors.Is(err, infrastructure.ErrRendererMissing) {
		t.Errorf("no renderer at all: %v", err)
	}
}
