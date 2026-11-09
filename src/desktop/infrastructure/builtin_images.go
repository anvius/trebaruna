package infrastructure

// Pictures for the built-in renderer: JPEG streams from their raw bytes,
// uncompressed and Flate streams in grey, RGB, CMYK, ICC and indexed
// colour, with their soft masks. Anything else (CCITT, JBIG2, encrypted
// files) stays a grey box.

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"regexp"

	"github.com/digitorus/pdf"
	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/math/f64"
)

// maxPicturePixels bounds a decoded picture: a 300 DPI A4 scan is under
// nine million pixels, and a crafted header must not allocate gigabytes.
const maxPicturePixels = 40_000_000

// picture decodes an image XObject, or reports it cannot.
func (s *pageSketch) picture(object pdf.Value) (image.Image, bool) {
	width, height := int(object.Key("Width").Int64()), int(object.Key("Height").Int64())
	if width <= 0 || height <= 0 || width*height > maxPicturePixels || object.Key("ImageMask").Bool() {
		return nil, false
	}
	var decoded image.Image
	switch filters := filterNames(object.Key("Filter")); {
	case len(filters) == 1 && filters[0] == "DCTDecode":
		raw, ok := s.rawStream(object)
		if !ok {
			return nil, false
		}
		picture, err := jpeg.Decode(bytes.NewReader(raw))
		if err != nil {
			return nil, false
		}
		decoded = picture
	case len(filters) == 0 || (len(filters) == 1 && filters[0] == "FlateDecode"):
		picture, ok := samples(object, width, height)
		if !ok {
			return nil, false
		}
		decoded = picture
	default:
		return nil, false
	}
	if mask := object.Key("SMask"); mask.Kind() == pdf.Stream {
		if alpha, ok := samples(mask, width, height); ok && alpha.Bounds() == decoded.Bounds() {
			return withAlpha(decoded, alpha), true
		}
	}
	return decoded, true
}

func filterNames(filter pdf.Value) []string {
	switch filter.Kind() {
	case pdf.Name:
		return []string{filter.Name()}
	case pdf.Array:
		names := make([]string, filter.Len())
		for index := range names {
			names[index] = filter.Index(index).Name()
		}
		return names
	}
	return nil
}

// samples reads an image's decoded samples into an image of its colour
// space: 8-bit grey, RGB or CMYK (ICC profiles by their component count),
// or indexed at 1, 2, 4 or 8 bits.
func samples(object pdf.Value, width, height int) (image.Image, bool) {
	reader := object.Reader()
	data, err := io.ReadAll(io.LimitReader(reader, int64(width*height*4)+1))
	reader.Close()
	if err != nil {
		return nil, false
	}
	bits := int(object.Key("BitsPerComponent").Int64())
	space := object.Key("ColorSpace")
	if space.IsNull() {
		space = object.Key("CS")
	}
	if palette, base, ok := indexed(space); ok {
		return indexedImage(data, width, height, bits, palette, base)
	}
	components := componentCount(space)
	if bits != 8 || components == 0 || len(data) < width*height*components {
		return nil, false
	}
	switch components {
	case 1:
		return &image.Gray{Pix: data[:width*height], Stride: width, Rect: image.Rect(0, 0, width, height)}, true
	case 3:
		picture := image.NewRGBA(image.Rect(0, 0, width, height))
		for pixel := 0; pixel < width*height; pixel++ {
			copy(picture.Pix[pixel*4:], data[pixel*3:pixel*3+3])
			picture.Pix[pixel*4+3] = 255
		}
		return picture, true
	default:
		picture := image.NewRGBA(image.Rect(0, 0, width, height))
		for pixel := 0; pixel < width*height; pixel++ {
			c, m, y, k := data[pixel*4], data[pixel*4+1], data[pixel*4+2], data[pixel*4+3]
			r, g, b := color.CMYKToRGB(c, m, y, k)
			picture.Pix[pixel*4], picture.Pix[pixel*4+1], picture.Pix[pixel*4+2], picture.Pix[pixel*4+3] = r, g, b, 255
		}
		return picture, true
	}
}

// componentCount is the number of colour components of a colour space.
func componentCount(space pdf.Value) int {
	name := space.Name()
	if space.Kind() == pdf.Array && space.Len() > 0 {
		name = space.Index(0).Name()
		if name == "ICCBased" {
			return int(space.Index(1).Key("N").Int64())
		}
	}
	switch name {
	case "DeviceGray", "CalGray", "G":
		return 1
	case "DeviceRGB", "CalRGB", "RGB":
		return 3
	case "DeviceCMYK", "CMYK":
		return 4
	}
	return 0
}

// indexed reads an [/Indexed base hival lookup] colour space.
func indexed(space pdf.Value) ([]byte, int, bool) {
	if space.Kind() != pdf.Array || space.Len() != 4 || (space.Index(0).Name() != "Indexed" && space.Index(0).Name() != "I") {
		return nil, 0, false
	}
	base := componentCount(space.Index(1))
	lookup := space.Index(3)
	var table []byte
	if lookup.Kind() == pdf.Stream {
		table = lookup.Data()
	} else {
		table = []byte(lookup.RawString())
	}
	return table, base, base == 1 || base == 3 || base == 4
}

func indexedImage(data []byte, width, height, bits int, palette []byte, base int) (image.Image, bool) {
	if bits != 1 && bits != 2 && bits != 4 && bits != 8 {
		return nil, false
	}
	stride := (width*bits + 7) / 8
	if len(data) < stride*height {
		return nil, false
	}
	picture := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			bit := x * bits
			index := int(data[y*stride+bit/8]>>(8-bits-bit%8)) & (1<<bits - 1)
			offset := index * base
			if offset+base > len(palette) {
				continue
			}
			var r, g, b uint8
			switch base {
			case 1:
				r, g, b = palette[offset], palette[offset], palette[offset]
			case 3:
				r, g, b = palette[offset], palette[offset+1], palette[offset+2]
			case 4:
				r, g, b = color.CMYKToRGB(palette[offset], palette[offset+1], palette[offset+2], palette[offset+3])
			}
			pixel := (y*width + x) * 4
			picture.Pix[pixel], picture.Pix[pixel+1], picture.Pix[pixel+2], picture.Pix[pixel+3] = r, g, b, 255
		}
	}
	return picture, true
}

// withAlpha applies a soft mask's grey levels as the picture's alpha.
func withAlpha(picture, mask image.Image) image.Image {
	bounds := picture.Bounds()
	masked := image.NewNRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := picture.At(x, y).RGBA()
			alpha, _, _, _ := mask.At(x, y).RGBA()
			masked.SetNRGBA(x, y, color.NRGBA{uint8(r >> 8), uint8(g >> 8), uint8(b >> 8), uint8(alpha >> 8)})
		}
	}
	return masked
}

// rawStream finds a stream's bytes as stored, for the filters the PDF
// library does not decode (JPEG). An image is always a top-level object,
// so its "N G obj … stream" is in the file; the last definition wins, as
// incremental updates add them at the end.
func (s *pageSketch) rawStream(object pdf.Value) ([]byte, bool) {
	length := int(object.Key("Length").Int64())
	pointer := object.GetPtr()
	if s.file == nil || length <= 0 || pointer.GetID() == 0 {
		return nil, false
	}
	header := regexp.MustCompile(fmt.Sprintf(`(?:^|[^0-9])%d\s+%d\s+obj\b`, pointer.GetID(), pointer.GetGen()))
	matches := header.FindAllIndex(s.file, -1)
	if len(matches) == 0 {
		return nil, false
	}
	body := s.file[matches[len(matches)-1][1]:]
	start := bytes.Index(body, []byte("stream"))
	if end := bytes.Index(body, []byte("endobj")); start < 0 || (end >= 0 && end < start) {
		return nil, false
	}
	start += len("stream")
	if start < len(body) && body[start] == '\r' {
		start++
	}
	if start < len(body) && body[start] == '\n' {
		start++
	}
	if start+length > len(body) {
		return nil, false
	}
	return body[start : start+length], true
}

// drawPicture draws a picture over the unit square the current matrix
// maps it to, its first row at the top.
func (s *pageSketch) drawPicture(picture image.Image) {
	bounds := picture.Bounds()
	toUnit := matrix{1 / float64(bounds.Dx()), 0, 0, -1 / float64(bounds.Dy()), 0, 1}
	total := toUnit.then(s.state.ctm).then(s.device)
	transform := f64.Aff3{total[0], total[2], total[4], total[1], total[3], total[5]}
	xdraw.ApproxBiLinear.Transform(s.canvas, transform, picture, bounds, xdraw.Over, nil)
}
