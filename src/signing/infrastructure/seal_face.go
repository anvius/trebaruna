package infrastructure

import (
	"fmt"
	"math"
	"strings"
	"sync"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/sfnt"
	"golang.org/x/image/math/fixed"
	"golang.org/x/text/encoding/charmap"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/helvetica"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/pdffield"
)

// sealFace is the type a seal is set in: how wide its text runs, and the
// font resources the seal's appearance declares as /Helv and /HeBo.
type sealFace interface {
	Width(text string, size float64, bold bool) float64
	Wrap(text string, maxWidth, size float64, bold bool) []string
	// fonts are the /Font entries and the new objects they refer to as
	// {{first}}, {{first+1}}…
	fonts(first int) (string, []pdffield.Object)
}

// standardFace is Helvetica, which every reader has: nothing embedded.
type standardFace struct{}

func (standardFace) Width(text string, size float64, bold bool) float64 {
	return helvetica.Width(text, size, bold)
}

func (standardFace) Wrap(text string, maxWidth, size float64, bold bool) []string {
	return helvetica.Wrap(text, maxWidth, size, bold)
}

func (standardFace) fonts(int) (string, []pdffield.Object) {
	return "/Helv << /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>" +
		" /HeBo << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>", nil
}

// embeddedFace is the Go fonts (BSD licence), embedded whole, as PDF/A
// asks of every font a document shows (ISO 19005-1, 6.3.4): TrueType in
// WinAnsi encoding, the widths read from the font program itself (6.3.6).
type embeddedFace struct{}

// goFont is a parsed Go font with what the PDF needs of it.
type goFont struct {
	name    string
	program []byte
	parsed  *sfnt.Font
	// widths are the WinAnsi codes 32–255 in thousandths of the em.
	widths    [224]int
	bounds    [4]int
	ascent    int
	descent   int
	capHeight int
}

var (
	goFontsOnce sync.Once
	goFonts     [2]*goFont
	goFontsErr  error
)

// loadGoFonts parses the regular and bold faces once.
func loadGoFonts() ([2]*goFont, error) {
	goFontsOnce.Do(func() {
		for index, face := range []struct {
			name    string
			program []byte
		}{{"GoRegular", goregular.TTF}, {"GoBold", gobold.TTF}} {
			loaded, err := parseGoFont(face.name, face.program)
			if err != nil {
				goFontsErr = err
				return
			}
			goFonts[index] = loaded
		}
	})
	return goFonts, goFontsErr
}

func parseGoFont(name string, program []byte) (*goFont, error) {
	parsed, err := sfnt.Parse(program)
	if err != nil {
		return nil, fmt.Errorf("the seal's font: %w", err)
	}
	var buffer sfnt.Buffer
	unitsPerEm := parsed.UnitsPerEm()
	em := fixed.Int26_6(int(unitsPerEm) << 6)
	loaded := &goFont{name: name, program: program, parsed: parsed}
	toThousandths := func(value fixed.Int26_6) int {
		return int(math.Round(float64(value) / 64 * 1000 / float64(unitsPerEm)))
	}
	for code := 32; code <= 255; code++ {
		character := charmap.Windows1252.DecodeByte(byte(code))
		glyph, err := parsed.GlyphIndex(&buffer, character)
		if err != nil {
			return nil, err
		}
		advance, err := parsed.GlyphAdvance(&buffer, glyph, em, font.HintingNone)
		if err != nil {
			return nil, err
		}
		loaded.widths[code-32] = toThousandths(advance)
	}
	bounds, err := parsed.Bounds(&buffer, em, font.HintingNone)
	if err != nil {
		return nil, err
	}
	// sfnt's y axis points down; a PDF's up.
	loaded.bounds = [4]int{toThousandths(bounds.Min.X), -toThousandths(bounds.Max.Y), toThousandths(bounds.Max.X), -toThousandths(bounds.Min.Y)}
	metrics, err := parsed.Metrics(&buffer, em, font.HintingNone)
	if err != nil {
		return nil, err
	}
	loaded.ascent, loaded.descent, loaded.capHeight = toThousandths(metrics.Ascent), -toThousandths(metrics.Descent), toThousandths(metrics.CapHeight)
	return loaded, nil
}

// width measures text as it is printed: WinAnsi, "?" for what it lacks.
func (f *goFont) width(text string, size float64) float64 {
	total := 0
	for _, code := range []byte(winAnsiOrQuestionMark(text)) {
		if code >= 32 {
			total += f.widths[code-32]
		}
	}
	return float64(total) * size / 1000
}

func (embeddedFace) Width(text string, size float64, bold bool) float64 {
	fonts, err := loadGoFonts()
	if err != nil {
		return helvetica.Width(text, size, bold)
	}
	if bold {
		return fonts[1].width(text, size)
	}
	return fonts[0].width(text, size)
}

func (face embeddedFace) Wrap(text string, maxWidth, size float64, bold bool) []string {
	return helvetica.WrapWith(text, maxWidth, func(part string) float64 { return face.Width(part, size, bold) })
}

// fonts writes each face as a TrueType font, its descriptor and its
// program: three objects per face.
func (embeddedFace) fonts(first int) (string, []pdffield.Object) {
	fonts, err := loadGoFonts()
	if err != nil {
		return standardFace{}.fonts(first)
	}
	var entries []string
	var objects []pdffield.Object
	for index, resource := range []string{"/Helv", "/HeBo"} {
		face := fonts[index]
		base := first + 3*index
		widths := make([]string, len(face.widths))
		for position, width := range face.widths {
			widths[position] = fmt.Sprint(width)
		}
		entries = append(entries, fmt.Sprintf("%s {{%d}}", resource, base))
		objects = append(objects,
			pdffield.Object{Dictionary: fmt.Sprintf("<< /Type /Font /Subtype /TrueType /BaseFont /%s /FirstChar 32 /LastChar 255 /Widths [%s] "+
				"/Encoding /WinAnsiEncoding /FontDescriptor {{%d}} >>", face.name, strings.Join(widths, " "), base+1)},
			pdffield.Object{Dictionary: fmt.Sprintf("<< /Type /FontDescriptor /FontName /%s /Flags 32 /FontBBox [%d %d %d %d] /ItalicAngle 0 "+
				"/Ascent %d /Descent %d /CapHeight %d /StemV 80 /FontFile2 {{%d}} >>", face.name, face.bounds[0], face.bounds[1], face.bounds[2],
				face.bounds[3], face.ascent, face.descent, face.capHeight, base+2)},
			pdffield.Object{Dictionary: fmt.Sprintf("<< /Length1 %d /Filter /FlateDecode >>", len(face.program)), Stream: deflate(face.program)},
		)
	}
	return strings.Join(entries, " "), objects
}
