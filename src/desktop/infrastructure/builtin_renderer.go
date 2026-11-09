package infrastructure

// This file carries no build tag: the renderer is plain Go, so the tests run
// it without a window.

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/digitorus/pdf"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
	"golang.org/x/image/vector"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
)

// BuiltInRenderer draws a page without any program outside trebaruna: its
// text where the PDF puts it, in Go's own typeface; its lines and shapes in
// their colours; its pictures as grey boxes; the appearance of its form
// fields and earlier signatures. It is a sketch rather than the page a PDF
// reader shows, enough to see where the free space is and to put the seal
// there. poppler, when installed, draws the real page.
type BuiltInRenderer struct {
	// Resolution is the DPI of the preview.
	Resolution int
	// RasterMaxWidth caps the ink map width.
	RasterMaxWidth int
}

// NewBuiltInRenderer builds the renderer at poppler's resolution.
func NewBuiltInRenderer() *BuiltInRenderer {
	return &BuiltInRenderer{Resolution: 110, RasterMaxWidth: 300}
}

// RenderPage draws one page and measures its ink.
func (r *BuiltInRenderer) RenderPage(ctx context.Context, documentPath string, page int) (application.PagePreview, error) {
	file, err := os.ReadFile(documentPath)
	if err != nil {
		return application.PagePreview{}, fmt.Errorf("read %s: %w", documentPath, err)
	}
	reader, err := pdf.NewReader(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		return application.PagePreview{}, fmt.Errorf("read %s: %w", documentPath, err)
	}
	count := reader.NumPage()
	if page < 1 || page > count {
		return application.PagePreview{}, fmt.Errorf("the document has %d pages, cannot preview page %d", count, page)
	}
	if err := ctx.Err(); err != nil {
		return application.PagePreview{}, err
	}

	source := reader.Page(page)
	box := visibleBox(source)
	width, height := box[2]-box[0], box[3]-box[1]
	scale := float64(r.Resolution) / 72
	canvas := image.NewRGBA(image.Rect(0, 0, int(math.Ceil(width*scale)), int(math.Ceil(height*scale))))
	draw.Draw(canvas, canvas.Bounds(), image.White, image.Point{}, draw.Src)

	sketch := newPageSketch(canvas, box, scale)
	if !reader.IsEncrypted() {
		sketch.file = file
	}
	sketch.contents(source.V.Key("Contents"), source.Resources(), identityMatrix, 0)
	sketch.annotations(source.V.Key("Annots"))

	var encoded bytes.Buffer
	if err := png.Encode(&encoded, canvas); err != nil {
		return application.PagePreview{}, err
	}
	ink, rasterWidth, rasterHeight, err := measureInk(encoded.Bytes(), r.RasterMaxWidth)
	if err != nil {
		return application.PagePreview{}, err
	}
	return application.PagePreview{
		PageNumber: page, WidthPoints: width, HeightPoints: height, PNG: encoded.Bytes(),
		RasterWidth: rasterWidth, RasterHeight: rasterHeight, Ink: ink, PageCount: count, Approximate: true,
	}, nil
}

// visibleBox is the page's crop box, or its media box, as llx lly urx ury;
// both may be inherited from the page tree.
func visibleBox(page pdf.Page) [4]float64 {
	for _, candidate := range []pdf.Value{inherited(page, "CropBox"), inherited(page, "MediaBox")} {
		if candidate.Kind() == pdf.Array && candidate.Len() == 4 {
			var box [4]float64
			for index := range box {
				box[index] = candidate.Index(index).Float64()
			}
			box = [4]float64{math.Min(box[0], box[2]), math.Min(box[1], box[3]), math.Max(box[0], box[2]), math.Max(box[1], box[3])}
			if box[2] > box[0] && box[3] > box[1] {
				return box
			}
		}
	}
	return [4]float64{0, 0, 595, 842}
}

// inherited reads a page attribute from the page or the nearest ancestor
// that sets it.
func inherited(page pdf.Page, key string) pdf.Value {
	for node, depth := page.V, 0; !node.IsNull() && depth < 32; node, depth = node.Key("Parent"), depth+1 {
		if value := node.Key(key); !value.IsNull() {
			return value
		}
	}
	return pdf.Value{}
}

// matrix is a PDF transformation [a b c d e f]: a point (x y) becomes
// (a·x + c·y + e, b·x + d·y + f).
type matrix [6]float64

var identityMatrix = matrix{1, 0, 0, 1, 0, 0}

// then applies m, then n: PDF writes it m × n.
func (m matrix) then(n matrix) matrix {
	return matrix{
		m[0]*n[0] + m[1]*n[2], m[0]*n[1] + m[1]*n[3],
		m[2]*n[0] + m[3]*n[2], m[2]*n[1] + m[3]*n[3],
		m[4]*n[0] + m[5]*n[2] + n[4], m[4]*n[1] + m[5]*n[3] + n[5],
	}
}

func (m matrix) apply(x, y float64) (float64, float64) {
	return m[0]*x + m[2]*y + m[4], m[1]*x + m[3]*y + m[5]
}

// matrixFrom reads a matrix from a PDF array.
func matrixFrom(array pdf.Value) (matrix, bool) {
	values := make([]pdf.Value, array.Len())
	for index := range values {
		values[index] = array.Index(index)
	}
	return matrixOf(values)
}

func matrixOf(values []pdf.Value) (matrix, bool) {
	if len(values) != 6 {
		return matrix{}, false
	}
	var m matrix
	for index := range m {
		m[index] = values[index].Float64()
	}
	return m, true
}

// sketchState is the graphics state the sketch follows.
type sketchState struct {
	ctm                                           matrix
	fill, stroke                                  color.RGBA
	lineWidth                                     float64
	font                                          *sketchFont
	fontSize, charSpace, wordSpace, scaling, rise float64
	leading                                       float64
	renderMode                                    int
}

// pageSketch draws content streams onto an image.
type pageSketch struct {
	canvas *image.RGBA
	// device maps user space onto the canvas: the visible box's lower-left
	// corner to the bottom of the image, y downwards.
	device matrix
	state  sketchState
	stack  []sketchState
	path   [][][2]float64
	text   struct{ matrix, line matrix }
	fonts  map[uint32]*sketchFont
	faces  map[faceKey]font.Face
	// file is the document as stored, for the streams the PDF library does
	// not decode; nil for an encrypted one.
	file []byte
}

type faceKey struct {
	bold bool
	size int
}

func newPageSketch(canvas *image.RGBA, box [4]float64, scale float64) *pageSketch {
	return &pageSketch{
		canvas: canvas,
		device: matrix{scale, 0, 0, -scale, -box[0] * scale, box[3] * scale},
		state:  sketchState{ctm: identityMatrix, fill: color.RGBA{A: 255}, stroke: color.RGBA{A: 255}, lineWidth: 1, scaling: 1},
		fonts:  map[uint32]*sketchFont{},
		faces:  map[faceKey]font.Face{},
	}
}

// maxFormDepth bounds nested forms, which a crafted file can make cyclic.
const maxFormDepth = 8

// contents interprets a page's or a form's streams with its resources,
// under a matrix. A stream that does not parse stops where it fails; the
// rest of the page is still drawn.
func (s *pageSketch) contents(streams pdf.Value, resources pdf.Value, base matrix, depth int) {
	if depth > maxFormDepth {
		return
	}
	saved := s.state
	s.state.ctm = base.then(s.state.ctm)
	list := []pdf.Value{streams}
	if streams.Kind() == pdf.Array {
		list = list[:0]
		for index := 0; index < streams.Len(); index++ {
			list = append(list, streams.Index(index))
		}
	}
	for _, stream := range list {
		s.interpret(stream, resources, depth)
	}
	s.state = saved
}

func (s *pageSketch) interpret(stream pdf.Value, resources pdf.Value, depth int) {
	defer func() { _ = recover() }()
	pdf.Interpret(stream, func(stack *pdf.Stack, operator string) {
		args := make([]pdf.Value, stack.Len())
		for index := len(args) - 1; index >= 0; index-- {
			args[index] = stack.Pop()
		}
		s.operator(operator, args, resources, depth)
	})
}

// operator applies one content-stream operator.
func (s *pageSketch) operator(operator string, args []pdf.Value, resources pdf.Value, depth int) {
	number := func(index int) float64 {
		if index < len(args) {
			return args[index].Float64()
		}
		return 0
	}
	switch operator {
	case "q":
		s.stack = append(s.stack, s.state)
	case "Q":
		if len(s.stack) > 0 {
			s.state, s.stack = s.stack[len(s.stack)-1], s.stack[:len(s.stack)-1]
		}
	case "cm":
		if m, ok := matrixOf(args); ok {
			s.state.ctm = m.then(s.state.ctm)
		}
	case "w":
		s.state.lineWidth = number(0)
	case "g":
		s.state.fill = colourOf(args)
	case "G":
		s.state.stroke = colourOf(args)
	case "rg", "k", "sc", "scn":
		s.state.fill = colourOf(args)
	case "RG", "K", "SC", "SCN":
		s.state.stroke = colourOf(args)
	case "cs":
		s.state.fill = color.RGBA{A: 255}
	case "CS":
		s.state.stroke = color.RGBA{A: 255}

	// Paths are kept in user space under the matrix of their construction.
	case "m":
		s.path = append(s.path, [][2]float64{s.point(number(0), number(1))})
	case "l":
		s.lineTo(s.point(number(0), number(1)))
	case "c":
		s.curveTo(s.point(number(0), number(1)), s.point(number(2), number(3)), s.point(number(4), number(5)))
	case "v":
		s.curveTo(s.current(), s.point(number(0), number(1)), s.point(number(2), number(3)))
	case "y":
		end := s.point(number(2), number(3))
		s.curveTo(s.point(number(0), number(1)), end, end)
	case "h":
		if last := len(s.path) - 1; last >= 0 && len(s.path[last]) > 0 {
			s.path[last] = append(s.path[last], s.path[last][0])
		}
	case "re":
		x, y, w, h := number(0), number(1), number(2), number(3)
		s.path = append(s.path, [][2]float64{s.point(x, y), s.point(x+w, y), s.point(x+w, y+h), s.point(x, y+h), s.point(x, y)})
	case "S", "s":
		s.strokePath()
		s.path = nil
	case "f", "F", "f*":
		s.fillPath()
		s.path = nil
	case "B", "B*", "b", "b*":
		s.fillPath()
		s.strokePath()
		s.path = nil
	case "n":
		s.path = nil

	case "BT":
		s.text.matrix, s.text.line = identityMatrix, identityMatrix
	case "Tf":
		if len(args) == 2 {
			s.state.font = s.font(resources, args[0].Name())
			s.state.fontSize = args[1].Float64()
		}
	case "Tc":
		s.state.charSpace = number(0)
	case "Tw":
		s.state.wordSpace = number(0)
	case "Tz":
		s.state.scaling = number(0) / 100
	case "TL":
		s.state.leading = number(0)
	case "Ts":
		s.state.rise = number(0)
	case "Tr":
		s.state.renderMode = int(number(0))
	case "Td":
		s.text.line = matrix{1, 0, 0, 1, number(0), number(1)}.then(s.text.line)
		s.text.matrix = s.text.line
	case "TD":
		s.state.leading = -number(1)
		s.text.line = matrix{1, 0, 0, 1, number(0), number(1)}.then(s.text.line)
		s.text.matrix = s.text.line
	case "Tm":
		if m, ok := matrixOf(args); ok {
			s.text.matrix, s.text.line = m, m
		}
	case "T*":
		s.nextLine()
	case "Tj":
		if len(args) == 1 {
			s.show(args[0].RawString())
		}
	case "'":
		s.nextLine()
		if len(args) == 1 {
			s.show(args[0].RawString())
		}
	case "\"":
		if len(args) == 3 {
			s.state.wordSpace, s.state.charSpace = args[0].Float64(), args[1].Float64()
			s.nextLine()
			s.show(args[2].RawString())
		}
	case "TJ":
		if len(args) == 1 && args[0].Kind() == pdf.Array {
			for index := 0; index < args[0].Len(); index++ {
				item := args[0].Index(index)
				if item.Kind() == pdf.String {
					s.show(item.RawString())
					continue
				}
				s.advance(-item.Float64() / 1000 * s.state.fontSize * s.state.scaling)
			}
		}

	case "Do":
		if len(args) == 1 {
			s.xobject(resources.Key("XObject").Key(args[0].Name()), resources, depth)
		}
	}
}

func (s *pageSketch) point(x, y float64) [2]float64 {
	px, py := s.state.ctm.apply(x, y)
	return [2]float64{px, py}
}

func (s *pageSketch) current() [2]float64 {
	if last := len(s.path) - 1; last >= 0 && len(s.path[last]) > 0 {
		return s.path[last][len(s.path[last])-1]
	}
	return [2]float64{}
}

func (s *pageSketch) lineTo(point [2]float64) {
	if len(s.path) == 0 {
		s.path = append(s.path, [][2]float64{point})
		return
	}
	last := len(s.path) - 1
	s.path[last] = append(s.path[last], point)
}

// curveTo flattens a Bézier curve into eight segments: plenty for a
// preview.
func (s *pageSketch) curveTo(first, second, end [2]float64) {
	start := s.current()
	for step := 1; step <= 8; step++ {
		t := float64(step) / 8
		u := 1 - t
		var point [2]float64
		for axis := range point {
			point[axis] = u*u*u*start[axis] + 3*u*u*t*first[axis] + 3*u*t*t*second[axis] + t*t*t*end[axis]
		}
		s.lineTo(point)
	}
}

func (s *pageSketch) toCanvas(point [2]float64) (float32, float32) {
	x, y := s.device.apply(point[0], point[1])
	return float32(x), float32(y)
}

func (s *pageSketch) fillPath() {
	rasterizer := s.rasterizer()
	for _, subpath := range s.path {
		if len(subpath) < 3 {
			continue
		}
		rasterizer.MoveTo(s.toCanvas(subpath[0]))
		for _, point := range subpath[1:] {
			rasterizer.LineTo(s.toCanvas(point))
		}
		rasterizer.ClosePath()
	}
	rasterizer.Draw(s.canvas, s.canvas.Bounds(), image.NewUniform(s.state.fill), image.Point{})
}

// strokePath draws each segment as a thin quadrilateral, at least a pixel
// wide.
func (s *pageSketch) strokePath() {
	// The line width scales with the matrix's average stretch.
	stretch := math.Sqrt(math.Abs(s.state.ctm[0]*s.state.ctm[3] - s.state.ctm[1]*s.state.ctm[2]))
	width := math.Max(s.state.lineWidth*stretch*math.Abs(s.device[0]), 1)
	rasterizer := s.rasterizer()
	for _, subpath := range s.path {
		for index := 1; index < len(subpath); index++ {
			x0, y0 := s.toCanvas(subpath[index-1])
			x1, y1 := s.toCanvas(subpath[index])
			dx, dy := float64(x1-x0), float64(y1-y0)
			length := math.Hypot(dx, dy)
			if length == 0 {
				continue
			}
			nx, ny := float32(-dy/length*width/2), float32(dx/length*width/2)
			rasterizer.MoveTo(x0+nx, y0+ny)
			rasterizer.LineTo(x1+nx, y1+ny)
			rasterizer.LineTo(x1-nx, y1-ny)
			rasterizer.LineTo(x0-nx, y0-ny)
			rasterizer.ClosePath()
		}
	}
	rasterizer.Draw(s.canvas, s.canvas.Bounds(), image.NewUniform(s.state.stroke), image.Point{})
}

func (s *pageSketch) rasterizer() *vector.Rasterizer {
	bounds := s.canvas.Bounds()
	return vector.NewRasterizer(bounds.Dx(), bounds.Dy())
}

func (s *pageSketch) nextLine() {
	s.text.line = matrix{1, 0, 0, 1, 0, -s.state.leading}.then(s.text.line)
	s.text.matrix = s.text.line
}

func (s *pageSketch) advance(distance float64) {
	s.text.matrix = matrix{1, 0, 0, 1, distance, 0}.then(s.text.matrix)
}

// show draws a string of character codes where the text matrix puts each
// one, then advances by the font's widths. Invisible text (render mode 3,
// the OCR layer over a scan) is measured but not drawn.
func (s *pageSketch) show(raw string) {
	current := s.state.font
	if current == nil {
		return
	}
	for _, code := range current.codes(raw) {
		glyph := matrix{s.state.fontSize * s.state.scaling, 0, 0, s.state.fontSize, 0, s.state.rise}.then(s.text.matrix).then(s.state.ctm)
		if s.state.renderMode != 3 {
			s.glyph(current, code, glyph)
		}
		distance := current.width(code)/1000*s.state.fontSize + s.state.charSpace
		if code.single && code.value == 32 {
			distance += s.state.wordSpace
		}
		s.advance(distance * s.state.scaling)
	}
}

// glyph draws one character with Go's typeface at the size and place the
// matrix gives, upright.
func (s *pageSketch) glyph(current *sketchFont, code characterCode, place matrix) {
	text := current.text(code)
	if strings.TrimSpace(text) == "" {
		return
	}
	size := math.Hypot(place[2], place[3]) * math.Abs(s.device[0])
	if size < 1 {
		return
	}
	face := s.face(current.bold, size)
	if face == nil {
		return
	}
	x, y := s.device.apply(place[4], place[5])
	drawer := font.Drawer{Dst: s.canvas, Src: image.NewUniform(s.state.fill), Face: face, Dot: fixed.P(int(x), int(y))}
	drawer.DrawString(text)
}

var typefaces = struct {
	regular, bold *opentype.Font
}{mustParse(goregular.TTF), mustParse(gobold.TTF)}

func mustParse(data []byte) *opentype.Font {
	parsed, err := opentype.Parse(data)
	if err != nil {
		panic(err)
	}
	return parsed
}

func (s *pageSketch) face(bold bool, size float64) font.Face {
	key := faceKey{bold: bold, size: int(math.Round(size))}
	if face, cached := s.faces[key]; cached {
		return face
	}
	typeface := typefaces.regular
	if bold {
		typeface = typefaces.bold
	}
	face, err := opentype.NewFace(typeface, &opentype.FaceOptions{Size: float64(key.size), DPI: 72, Hinting: font.HintingNone})
	if err != nil {
		return nil
	}
	s.faces[key] = face
	return face
}

// xobject draws a form, or a picture as a grey box over the unit square
// the matrix maps it to.
func (s *pageSketch) xobject(object pdf.Value, resources pdf.Value, depth int) {
	switch object.Key("Subtype").Name() {
	case "Form":
		formResources := object.Key("Resources")
		if formResources.Kind() != pdf.Dict {
			formResources = resources
		}
		base, ok := matrixFrom(object.Key("Matrix"))
		if !ok {
			base = identityMatrix
		}
		s.contents(object, formResources, base, depth+1)
	case "Image":
		if picture, ok := s.picture(object); ok {
			s.drawPicture(picture)
			return
		}
		saved, path := s.state, s.path
		s.path = [][][2]float64{{s.point(0, 0), s.point(1, 0), s.point(1, 1), s.point(0, 1), s.point(0, 0)}}
		s.state.fill, s.state.stroke, s.state.lineWidth = color.RGBA{214, 214, 214, 255}, color.RGBA{150, 150, 150, 255}, 0
		s.fillPath()
		s.strokePath()
		s.state, s.path = saved, path
	}
}

// annotations draws the normal appearance of each annotation (form
// fields, earlier visible signatures) in its rectangle.
func (s *pageSketch) annotations(list pdf.Value) {
	for index := 0; index < list.Len(); index++ {
		annotation := list.Index(index)
		appearance := annotation.Key("AP").Key("N")
		if appearance.Kind() != pdf.Stream || annotation.Key("F").Int64()&2 != 0 {
			continue
		}
		rect, bbox := annotation.Key("Rect"), appearance.Key("BBox")
		if rect.Len() != 4 || bbox.Len() != 4 {
			continue
		}
		bw, bh := bbox.Index(2).Float64()-bbox.Index(0).Float64(), bbox.Index(3).Float64()-bbox.Index(1).Float64()
		rw, rh := rect.Index(2).Float64()-rect.Index(0).Float64(), rect.Index(3).Float64()-rect.Index(1).Float64()
		if bw == 0 || bh == 0 {
			continue
		}
		fit := matrix{rw / bw, 0, 0, rh / bh,
			rect.Index(0).Float64() - bbox.Index(0).Float64()*rw/bw, rect.Index(1).Float64() - bbox.Index(1).Float64()*rh/bh}
		resources := appearance.Key("Resources")
		s.contents(appearance, resources, fit, 1)
	}
}

// colourOf reads a grey, RGB or CMYK colour from operands; anything else
// (a pattern) is drawn grey.
func colourOf(args []pdf.Value) color.RGBA {
	value := func(index int) float64 { return math.Max(0, math.Min(1, args[index].Float64())) }
	switch {
	case len(args) == 1 && args[0].Kind() != pdf.Name:
		grey := uint8(value(0) * 255)
		return color.RGBA{grey, grey, grey, 255}
	case len(args) == 3:
		return color.RGBA{uint8(value(0) * 255), uint8(value(1) * 255), uint8(value(2) * 255), 255}
	case len(args) == 4:
		k := value(3)
		return color.RGBA{uint8((1 - value(0)) * (1 - k) * 255), uint8((1 - value(1)) * (1 - k) * 255), uint8((1 - value(2)) * (1 - k) * 255), 255}
	}
	return color.RGBA{128, 128, 128, 255}
}

// characterCode is one code of a string shown with a font: a byte, or two
// for a composite font.
type characterCode struct {
	value  uint32
	single bool
}

// sketchFont is what the sketch needs of a font: how its strings split into
// codes, the width and the text of each code, and whether it is bold.
type sketchFont struct {
	composite    bool
	firstChar    int
	widths       []float64
	cidWidths    map[uint32]float64
	defaultWidth float64
	toUnicode    map[uint32]string
	differences  pdf.Font
	hasEncoding  bool
	bold         bool
}

// font loads a font resource, once per font object.
func (s *pageSketch) font(resources pdf.Value, name string) *sketchFont {
	object := resources.Key("Font").Key(name)
	id := object.GetPtr().GetID()
	if cached, ok := s.fonts[id]; ok && id != 0 {
		return cached
	}
	loaded := loadFont(object)
	s.fonts[id] = loaded
	return loaded
}

func loadFont(object pdf.Value) *sketchFont {
	loaded := &sketchFont{defaultWidth: 1000, toUnicode: parseToUnicode(object.Key("ToUnicode"))}
	base := object.Key("BaseFont").Name()
	loaded.bold = strings.Contains(strings.ToLower(base), "bold")
	if object.Key("Subtype").Name() == "Type0" {
		loaded.composite = true
		descendant := object.Key("DescendantFonts").Index(0)
		if width := descendant.Key("DW"); width.Kind() == pdf.Integer || width.Kind() == pdf.Real {
			loaded.defaultWidth = width.Float64()
		}
		loaded.cidWidths = cidWidths(descendant.Key("W"))
		return loaded
	}
	loaded.firstChar = int(object.Key("FirstChar").Int64())
	widths := object.Key("Widths")
	for index := 0; index < widths.Len(); index++ {
		loaded.widths = append(loaded.widths, widths.Index(index).Float64())
	}
	if object.Key("Encoding").Kind() == pdf.Dict {
		loaded.differences, loaded.hasEncoding = pdf.Font{V: object}, true
	}
	return loaded
}

// cidWidths reads a composite font's W array: "c [w1 w2 …]" and
// "cfirst clast w".
func cidWidths(array pdf.Value) map[uint32]float64 {
	widths := map[uint32]float64{}
	for index := 0; index+1 < array.Len(); {
		first := uint32(array.Index(index).Int64())
		next := array.Index(index + 1)
		if next.Kind() == pdf.Array {
			for offset := 0; offset < next.Len(); offset++ {
				widths[first+uint32(offset)] = next.Index(offset).Float64()
			}
			index += 2
			continue
		}
		if index+2 >= array.Len() {
			break
		}
		last, width := uint32(next.Int64()), array.Index(index+2).Float64()
		for code := first; code <= last && code-first < 65536; code++ {
			widths[code] = width
		}
		index += 3
	}
	return widths
}

func (f *sketchFont) codes(raw string) []characterCode {
	var codes []characterCode
	if f.composite {
		for index := 0; index+1 < len(raw); index += 2 {
			codes = append(codes, characterCode{value: uint32(raw[index])<<8 | uint32(raw[index+1])})
		}
		return codes
	}
	for index := 0; index < len(raw); index++ {
		codes = append(codes, characterCode{value: uint32(raw[index]), single: true})
	}
	return codes
}

func (f *sketchFont) width(code characterCode) float64 {
	if f.composite {
		if width, ok := f.cidWidths[code.value]; ok {
			return width
		}
		return f.defaultWidth
	}
	if index := int(code.value) - f.firstChar; index >= 0 && index < len(f.widths) {
		return f.widths[index]
	}
	return 500
}

// text is what a code reads as: ToUnicode first, then the font's
// differences, then the byte as Windows-1252, the encoding most documents
// use; a composite font without ToUnicode reads as a neutral mark.
func (f *sketchFont) text(code characterCode) string {
	if text, ok := f.toUnicode[code.value]; ok {
		return text
	}
	switch {
	case f.composite:
		return "•"
	case f.hasEncoding:
		return f.differences.Encoder().Decode(string([]byte{byte(code.value)}))
	}
	return windows1252(byte(code.value))
}

// windows1252 decodes a byte: Latin-1 but for the printable 0x80–0x9F block.
func windows1252(b byte) string {
	if b >= 0x80 && b < 0xA0 {
		return string(cp1252High[b-0x80])
	}
	return string(rune(b))
}

var cp1252High = []rune("€\u0081‚ƒ„…†‡ˆ‰Š‹Œ\u008dŽ\u008f\u0090‘’“”•–—˜™š›œ\u009džŸ")

// toUnicodeEntries finds the bfchar and bfrange sections of a ToUnicode CMap.
var (
	cmapSection = regexp.MustCompile(`(?s)begin(bfchar|bfrange)(.*?)end(?:bfchar|bfrange)`)
	cmapToken   = regexp.MustCompile(`<([0-9A-Fa-f\s]*)>|\[|\]`)
)

// parseToUnicode reads a ToUnicode CMap's character and range mappings.
func parseToUnicode(stream pdf.Value) map[uint32]string {
	mapping := map[uint32]string{}
	if stream.Kind() != pdf.Stream {
		return mapping
	}
	var data bytes.Buffer
	reader := stream.Reader()
	_, _ = data.ReadFrom(reader)
	reader.Close()
	for _, section := range cmapSection.FindAllStringSubmatch(data.String(), -1) {
		tokens := cmapToken.FindAllStringSubmatch(section[2], -1)
		if section[1] == "bfchar" {
			for index := 0; index+1 < len(tokens); index += 2 {
				mapping[hexNumber(tokens[index][1])] = utf16Text(tokens[index+1][1])
			}
			continue
		}
		for index := 0; index+2 < len(tokens); {
			low, high := hexNumber(tokens[index][1]), hexNumber(tokens[index+1][1])
			if tokens[index+2][0] == "[" {
				index += 3
				for code := low; index < len(tokens) && tokens[index][0] != "]"; code, index = code+1, index+1 {
					mapping[code] = utf16Text(tokens[index][1])
				}
				index++
				continue
			}
			start := utf16Units(tokens[index+2][1])
			for code := low; code <= high && code-low < 65536 && len(start) > 0; code++ {
				units := append([]uint16{}, start...)
				units[len(units)-1] += uint16(code - low)
				mapping[code] = string(utf16.Decode(units))
			}
			index += 3
		}
	}
	return mapping
}

func hexNumber(hexadecimal string) uint32 {
	value, _ := strconv.ParseUint(strings.Join(strings.Fields(hexadecimal), ""), 16, 32)
	return uint32(value)
}

func utf16Units(hexadecimal string) []uint16 {
	digits := strings.Join(strings.Fields(hexadecimal), "")
	var units []uint16
	for index := 0; index+4 <= len(digits); index += 4 {
		unit, err := strconv.ParseUint(digits[index:index+4], 16, 16)
		if err != nil {
			return nil
		}
		units = append(units, uint16(unit))
	}
	return units
}

func utf16Text(hexadecimal string) string { return string(utf16.Decode(utf16Units(hexadecimal))) }

var _ application.DocumentRenderer = (*BuiltInRenderer)(nil)
