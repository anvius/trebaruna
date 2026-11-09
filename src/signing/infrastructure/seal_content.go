package infrastructure

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg" // a rubric may be a JPEG
	_ "image/png"  // or a PNG
	"strings"

	"golang.org/x/text/encoding/charmap"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/pdffield"
)

// fieldAppearance draws the marks as a PDF form XObject of their box: the
// seal trebaruna puts in an existing signature field. Text is set in the
// standard Helvetica faces, which every reader has, in WinAnsi encoding.
func (m sealMarks) fieldAppearance() (*pdffield.Appearance, error) {
	var content bytes.Buffer
	appearance := &pdffield.Appearance{}
	var resources strings.Builder
	resources.WriteString("<< /Font << /Helv << /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>" +
		" /HeBo << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >> >>")

	if m.rubric != nil {
		objects, err := pictureObjects(m.rubric.data)
		if err != nil {
			return nil, err
		}
		appearance.Objects = objects
		resources.WriteString(" /XObject << /Rubric {{0}} >>")
		fmt.Fprintf(&content, "q %s 0 0 %s %s %s cm /Rubric Do Q\n",
			pdfNumber(m.rubric.width), pdfNumber(m.rubric.height), pdfNumber(m.rubric.x), pdfNumber(m.rubric.y))
	}
	resources.WriteString(" >>")

	fmt.Fprintf(&content, "q %s RG %s w %s %s m %s %s l S Q\n", rgb(m.rule.colour), pdfNumber(m.rule.width),
		pdfNumber(m.rule.x), pdfNumber(m.rule.bottom), pdfNumber(m.rule.x), pdfNumber(m.rule.top))
	encoder := charmap.Windows1252.NewEncoder()
	for _, text := range m.texts {
		font := "/Helv"
		if text.bold {
			font = "/HeBo"
		}
		encoded, err := encoder.String(text.content)
		if err != nil {
			// A character Helvetica's WinAnsi encoding lacks: each is
			// replaced, as the PDF library does.
			encoded = winAnsiOrQuestionMark(text.content)
		}
		fmt.Fprintf(&content, "BT %s %s Tf %s rg %s %s Td <%X> Tj ET\n", font, pdfNumber(text.size), rgb(text.colour),
			pdfNumber(text.x), pdfNumber(text.y), []byte(encoded))
	}
	appearance.Content = content.Bytes()
	appearance.Resources = resources.String()
	return appearance, nil
}

// winAnsiOrQuestionMark encodes rune by rune, "?" for what WinAnsi lacks.
func winAnsiOrQuestionMark(text string) string {
	var out strings.Builder
	for _, character := range text {
		if encoded, ok := charmap.Windows1252.EncodeRune(character); ok {
			out.WriteByte(encoded)
			continue
		}
		out.WriteByte('?')
	}
	return out.String()
}

// pictureObjects is the rubric as an image XObject: a colour JPEG as is,
// anything else as Flate-compressed RGB with its transparency as a soft
// mask ({{1}}).
func pictureObjects(data []byte) ([]pdffield.Object, error) {
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("read the rubric: %w", err)
	}
	if format == "jpeg" && config.ColorModel == color.YCbCrModel {
		return []pdffield.Object{{
			Dictionary: fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode >>",
				config.Width, config.Height),
			Stream: data,
		}}, nil
	}
	decoded, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("read the rubric: %w", err)
	}
	bounds := decoded.Bounds()
	picture := image.NewNRGBA(bounds)
	draw.Draw(picture, bounds, decoded, bounds.Min, draw.Src)
	samples := make([]byte, 0, bounds.Dx()*bounds.Dy()*3)
	alpha := make([]byte, 0, bounds.Dx()*bounds.Dy())
	opaque := true
	for pixel := 0; pixel < len(picture.Pix); pixel += 4 {
		samples = append(samples, picture.Pix[pixel], picture.Pix[pixel+1], picture.Pix[pixel+2])
		alpha = append(alpha, picture.Pix[pixel+3])
		opaque = opaque && picture.Pix[pixel+3] == 255
	}
	header := fmt.Sprintf("/Type /XObject /Subtype /Image /Width %d /Height %d /BitsPerComponent 8 /Filter /FlateDecode", bounds.Dx(), bounds.Dy())
	objects := []pdffield.Object{{Dictionary: "<< " + header + " /ColorSpace /DeviceRGB >>", Stream: deflate(samples)}}
	if !opaque {
		objects[0].Dictionary = "<< " + header + " /ColorSpace /DeviceRGB /SMask {{1}} >>"
		objects = append(objects, pdffield.Object{Dictionary: "<< " + header + " /ColorSpace /DeviceGray >>", Stream: deflate(alpha)})
	}
	return objects, nil
}

func deflate(data []byte) []byte {
	var out bytes.Buffer
	writer := zlib.NewWriter(&out)
	writer.Write(data)
	writer.Close()
	return out.Bytes()
}

func rgb(colour [3]uint8) string {
	return fmt.Sprintf("%s %s %s", pdfNumber(float64(colour[0])/255), pdfNumber(float64(colour[1])/255), pdfNumber(float64(colour[2])/255))
}

// pdfNumber writes a number as PDF content streams take it.
func pdfNumber(value float64) string {
	text := fmt.Sprintf("%.3f", value)
	text = strings.TrimRight(strings.TrimRight(text, "0"), ".")
	if text == "" || text == "-0" {
		return "0"
	}
	return text
}
