//go:build gui

package infrastructure

import (
	"image"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// SealIdentity is the text the seal will print, taken from the certificate.
type SealIdentity struct {
	Name       string
	Identifier string
}

// PageCanvas draws one page and the seal on top of it, and lets the user put
// the seal where it belongs with the pointer or the keyboard.
//
//   - a click on the paper centres the seal under the pointer;
//   - dragging the seal moves it, dragging its corner handle enlarges it;
//   - dragging on empty paper drops the seal there and keeps moving it;
//   - with the canvas focused, the arrow keys nudge it two points, and +
//     and - grow and shrink it.
//
// The page image is drawn by this widget, not by a separate canvas.Image with
// its own fit: the page and the pointer must share one DisplayFit, and the
// old overlay drifted from the cursor precisely because they did not.
type PageCanvas struct {
	widget.BaseWidget

	geometry domain.PageGeometry
	ink      domain.InkMap
	page     image.Image
	rect     domain.SealRect
	identity SealIdentity
	// rubric and its picture are drawn beside the data, as the signer will.
	rubric        signing.Rubric
	rubricPicture image.Image
	moment        time.Time
	onChange      func(domain.SealRect)
	// description is what a screen reader says for the page: how to place
	// the seal, or that it covers text.
	description string

	// fit is recomputed on every layout; pointer events read it.
	fit     domain.DisplayFit
	gesture gesture
	hover   zone
	focused bool
}

// gesture is what the current drag does.
type gesture int

const (
	gestureNone gesture = iota
	gestureMove
	gestureGrow
	gestureIgnore
)

// zone is what lies under the pointer.
type zone int

const (
	zoneOutside zone = iota
	zonePaper
	zoneSeal
	zoneHandle
)

// faceCompensation shrinks Fyne's default face to Helvetica's advance widths.
const faceCompensation = 0.9

// handleSize is the side of the corner handle, in screen units. Generous on
// purpose: a 6 px target on a 40 px seal is a test of dexterity.
const handleSize = 12

// The seal is drawn with the colours the signer prints, so the preview is the
// result and not a placeholder for it.
var (
	sealInk     = color.NRGBA{R: 38, G: 84, B: 124, A: 255}
	sealName    = color.NRGBA{R: 16, G: 20, B: 26, A: 255}
	sealDetail  = color.NRGBA{R: 78, G: 86, B: 96, A: 255}
	sealVeil    = color.NRGBA{R: 255, G: 255, B: 255, A: 215}
	sealWarning = color.NRGBA{R: 196, G: 120, B: 20, A: 255}
	paperShadow = color.NRGBA{R: 0, G: 0, B: 0, A: 90}
)

// NewPageCanvas builds the canvas for one rendered page.
func NewPageCanvas(
	geometry domain.PageGeometry,
	ink domain.InkMap,
	page image.Image,
	rect domain.SealRect,
	identity SealIdentity,
	onChange func(domain.SealRect),
) *PageCanvas {
	pageCanvas := &PageCanvas{
		geometry: geometry,
		ink:      ink,
		page:     page,
		rect:     geometry.Clamp(rect),
		identity: identity,
		moment:   time.Now(),
		onChange: onChange,
	}
	pageCanvas.ExtendBaseWidget(pageCanvas)
	return pageCanvas
}

// Rect returns the seal rectangle in PDF points.
func (p *PageCanvas) Rect() domain.SealRect { return p.rect }

// CoversText reports whether the seal sits on printed content.
func (p *PageCanvas) CoversText() bool { return p.geometry.Covers(p.ink, p.rect) }

// SetRect moves the seal, after a suggestion is picked.
func (p *PageCanvas) SetRect(rect domain.SealRect) {
	p.rect = p.geometry.Clamp(rect)
	p.changed()
}

// SetIdentity updates the printed identity once the certificate is read.
func (p *PageCanvas) SetIdentity(identity SealIdentity) {
	p.identity = identity
	p.Refresh()
}

// SetDescription sets what a screen reader says for the page.
func (p *PageCanvas) SetDescription(description string) { p.description = description }

// AccessibilityLabel is the page's description (Fyne's accessibility, on
// the platforms it reaches).
func (p *PageCanvas) AccessibilityLabel() string { return p.description }

// AccessibilityRole is text: Fyne has no role for a placement surface.
func (p *PageCanvas) AccessibilityRole() fyne.AccessibleRole { return fyne.AccessibleRoleText }

// SetRubric shows the rubric the seal will carry; a zero one removes it.
func (p *PageCanvas) SetRubric(rubric signing.Rubric, picture image.Image) {
	p.rubric, p.rubricPicture = rubric, picture
	p.Refresh()
}

// Tapped centres the seal under the pointer when the click lands on paper.
func (p *PageCanvas) Tapped(event *fyne.PointEvent) {
	p.requestFocus()
	if p.zoneAt(event.Position) != zonePaper {
		return
	}
	p.rect = p.fit.CentredAt(float64(event.Position.X), float64(event.Position.Y), p.rect.Width(), p.rect.Height())
	p.changed()
}

// Dragged moves or enlarges the seal; the gesture is decided where it began.
func (p *PageCanvas) Dragged(event *fyne.DragEvent) {
	if p.gesture == gestureNone {
		start := event.Position.Subtract(event.Dragged)
		switch p.zoneAt(start) {
		case zoneHandle:
			p.gesture = gestureGrow
		case zoneSeal:
			p.gesture = gestureMove
		case zonePaper:
			p.gesture = gestureMove
			p.rect = p.fit.CentredAt(float64(start.X), float64(start.Y), p.rect.Width(), p.rect.Height())
		default:
			p.gesture = gestureIgnore
		}
	}

	deltaX, deltaY := float64(event.Dragged.DX), float64(event.Dragged.DY)
	switch p.gesture {
	case gestureMove:
		p.rect = p.fit.Move(p.rect, deltaX, deltaY)
	case gestureGrow:
		p.rect = p.fit.Grow(p.rect, deltaX, deltaY)
	default:
		return
	}
	p.changed()
}

// DragEnd closes the gesture.
func (p *PageCanvas) DragEnd() { p.gesture = gestureNone }

// MouseIn tracks the pointer for the cursor.
func (p *PageCanvas) MouseIn(event *desktop.MouseEvent) { p.hover = p.zoneAt(event.Position) }

// MouseMoved tracks the pointer for the cursor.
func (p *PageCanvas) MouseMoved(event *desktop.MouseEvent) { p.hover = p.zoneAt(event.Position) }

// MouseOut forgets the pointer.
func (p *PageCanvas) MouseOut() { p.hover = zoneOutside }

// Cursor tells the user what a press will do before they press.
func (p *PageCanvas) Cursor() desktop.Cursor {
	switch p.hover {
	case zoneHandle:
		return desktop.NWSEResizeCursor
	case zoneSeal:
		return desktop.PointerCursor
	case zonePaper:
		return desktop.CrosshairCursor
	}
	return desktop.DefaultCursor
}

// FocusGained shows the focus ring: keyboard users must see where they are.
func (p *PageCanvas) FocusGained() { p.focused = true; p.Refresh() }

// FocusLost hides the focus ring.
func (p *PageCanvas) FocusLost() { p.focused = false; p.Refresh() }

// TypedRune grows the seal with + (or =, the same key unshifted) and shrinks
// it with -, keeping its proportions: the keyboard's way to do what the
// corner handle does, for whoever cannot drag (WCAG 2.5.7).
func (p *PageCanvas) TypedRune(typed rune) {
	const step = 4.0
	var sign float64
	switch typed {
	case '+', '=':
		sign = 1
	case '-':
		sign = -1
	default:
		return
	}
	ratio := p.rect.Height() / p.rect.Width()
	p.rect = p.fit.Grow(p.rect, sign*step*p.fit.Scale, sign*step*ratio*p.fit.Scale)
	p.changed()
}

// TypedKey nudges the seal with the arrow keys.
func (p *PageCanvas) TypedKey(event *fyne.KeyEvent) {
	const step = 2.0
	var deltaX, deltaY float64
	switch event.Name {
	case fyne.KeyLeft:
		deltaX = -step
	case fyne.KeyRight:
		deltaX = step
	case fyne.KeyUp:
		deltaY = step
	case fyne.KeyDown:
		deltaY = -step
	default:
		return
	}
	p.rect = p.geometry.Clamp(p.rect.MoveBy(deltaX, deltaY))
	p.changed()
}

// zoneAt classifies a point in widget coordinates.
func (p *PageCanvas) zoneAt(position fyne.Position) zone {
	x, y := float64(position.X), float64(position.Y)
	seal := p.fit.ToScreen(p.rect)
	handle := domain.Rectangle{
		X: seal.X + seal.Width - handleSize, Y: seal.Y + seal.Height - handleSize,
		Width: handleSize + 4, Height: handleSize + 4,
	}
	switch {
	case handle.Contains(x, y):
		return zoneHandle
	case seal.Contains(x, y):
		return zoneSeal
	case p.fit.PageArea().Contains(x, y):
		return zonePaper
	}
	return zoneOutside
}

func (p *PageCanvas) requestFocus() {
	if app := fyne.CurrentApp(); app != nil {
		if owner := app.Driver().CanvasForObject(p); owner != nil {
			owner.Focus(p)
		}
	}
}

func (p *PageCanvas) changed() {
	p.Refresh()
	if p.onChange != nil {
		p.onChange(p.rect)
	}
}

// MinSize leaves room for a legible page.
func (p *PageCanvas) MinSize() fyne.Size { return fyne.NewSize(320, 420) }

// CreateRenderer builds the drawing.
func (p *PageCanvas) CreateRenderer() fyne.WidgetRenderer {
	paper := canvas.NewImageFromImage(p.page)
	paper.FillMode = canvas.ImageFillStretch
	paper.ScaleMode = canvas.ImageScaleSmooth

	frame := canvas.NewRectangle(color.Transparent)
	frame.StrokeWidth = 1.5
	focusRing := canvas.NewRectangle(color.Transparent)
	focusRing.StrokeWidth = 2

	handle := canvas.NewRectangle(sealInk)
	handle.StrokeColor = color.White
	handle.StrokeWidth = 1.5

	rubric := canvas.NewImageFromImage(nil)
	rubric.FillMode = canvas.ImageFillStretch
	rubric.ScaleMode = canvas.ImageScaleSmooth

	renderer := &pageCanvasRenderer{
		canvas:    p,
		rubric:    rubric,
		shadow:    canvas.NewRectangle(paperShadow),
		paper:     paper,
		veil:      canvas.NewRectangle(sealVeil),
		bar:       canvas.NewRectangle(sealInk),
		frame:     frame,
		focusRing: focusRing,
		handle:    handle,
	}
	renderer.applyState()
	return renderer
}

// pageCanvasRenderer lays the page out with the shared fit.
type pageCanvasRenderer struct {
	canvas    *PageCanvas
	shadow    *canvas.Rectangle
	paper     *canvas.Image
	veil      *canvas.Rectangle
	rubric    *canvas.Image
	bar       *canvas.Rectangle
	frame     *canvas.Rectangle
	focusRing *canvas.Rectangle
	handle    *canvas.Rectangle
	lines     []*canvas.Text
	objects   []fyne.CanvasObject
}

// Layout recomputes the fit for the new size and places everything.
func (r *pageCanvasRenderer) Layout(size fyne.Size) {
	p := r.canvas
	p.fit = p.geometry.FitInto(float64(size.Width), float64(size.Height))
	area := p.fit.PageArea()

	place(r.shadow, area.X+2, area.Y+3, area.Width, area.Height)
	place(r.paper, area.X, area.Y, area.Width, area.Height)

	seal := p.fit.ToScreen(p.rect)
	place(r.veil, seal.X, seal.Y, seal.Width, seal.Height)
	place(r.frame, seal.X, seal.Y, seal.Width, seal.Height)
	place(r.focusRing, seal.X-4, seal.Y-4, seal.Width+8, seal.Height+8)
	place(r.handle, seal.X+seal.Width-handleSize/2-2, seal.Y+seal.Height-handleSize/2-2, handleSize/2+2, handleSize/2+2)

	r.layoutStamp(seal)
}

// layoutStamp mirrors the signer's typography (signing/infrastructure/seal.go):
// the scale follows the box height, the name is bold and wraps, identifier and
// date share a line when they fit, the time comes last.
//
// Fyne's face is wider than Helvetica, so glyphs are drawn at faceCompensation
// of the PDF size: line breaks then fall where the signer puts them, which
// matters more in a preview than a few percent of glyph height.
func (r *pageCanvasRenderer) layoutStamp(seal domain.Rectangle) {
	p := r.canvas
	scale := p.rect.Height() / 48.0
	if p.rect.Width() < p.rect.Height()*1.2 {
		scale *= 0.92
	}
	nameSize, detailSize, timeSize := 5.6*scale, 4.6*scale, 4.4*scale
	leading, gap := 5.4*scale, 1.6*scale
	if nameSize > 11 {
		factor := 11 / nameSize
		nameSize, detailSize, timeSize, leading, gap = 11, detailSize*factor, timeSize*factor, leading*factor, gap*factor
	}

	toScreen := p.fit.Scale
	padding := 2.6

	// The rubric goes where the signer puts it, and the data start after it.
	left := 0.0
	r.rubric.Hide()
	if box, dataLeft, ok := p.rubric.Fit(p.rect.Width(), p.rect.Height(), padding); ok && p.rubricPicture != nil {
		r.rubric.Image = p.rubricPicture
		place(r.rubric, seal.X+box.X*toScreen, seal.Y+(p.rect.Height()-box.Y-box.Height)*toScreen, box.Width*toScreen, box.Height*toScreen)
		r.rubric.Show()
		left = dataLeft
	}
	textLeft := seal.X + (left+padding+3.2)*toScreen
	innerWidth := (p.rect.Width() - left - 2*padding - 3.2) * toScreen

	place(r.bar, seal.X+(left+1.2)*toScreen, seal.Y+1.2*toScreen, 1.8*toScreen, seal.Height-2.4*toScreen)

	nameStyle, detailStyle := fyne.TextStyle{Bold: true}, fyne.TextStyle{}
	glyph := toScreen * faceCompensation
	names := wrapForScreen(p.identity.Name, float32(nameSize*glyph), nameStyle, float32(innerWidth))

	date := p.moment.Format("02/01/2006")
	var details []string
	switch combined := p.identity.Identifier + " · " + date; {
	case p.identity.Identifier == "":
		details = []string{date}
	case fyne.MeasureText(combined, float32(detailSize*glyph), detailStyle).Width <= float32(innerWidth):
		details = []string{combined}
	default:
		details = append(wrapForScreen(p.identity.Identifier, float32(detailSize*glyph), detailStyle, float32(innerWidth)), date)
	}
	details = append(details, p.moment.Format("15:04:05 -07:00"))

	total := float64(len(names))*leading + gap + float64(len(details))*leading
	top := (p.rect.Height() - total) / 2

	r.lines = r.lines[:0]
	baseline := top + nameSize
	for _, line := range names {
		r.lines = append(r.lines, stampText(line, sealName, nameSize*glyph, nameStyle, textLeft, seal.Y+baseline*toScreen))
		baseline += leading
	}
	// The first detail sits below the last name line, not below the first:
	// one leading back, then the gap and the detail ascent.
	baseline += gap + detailSize - leading
	for index, line := range details {
		size := detailSize
		if index == len(details)-1 {
			size = timeSize
		}
		r.lines = append(r.lines, stampText(line, sealDetail, size*glyph, detailStyle, textLeft, seal.Y+baseline*toScreen))
		baseline += leading
	}
}

// stampText places a line by its baseline, as the PDF does.
func stampText(text string, colour color.Color, size float64, style fyne.TextStyle, left, baseline float64) *canvas.Text {
	line := canvas.NewText(text, colour)
	line.TextSize = float32(size)
	line.TextStyle = style
	// Fyne positions text by the top of its line box; the ascent of the
	// default face is about 0.8 of the size, which puts the baseline right.
	line.Move(fyne.NewPos(float32(left), float32(baseline-size*0.95)))
	return line
}

// wrapForScreen breaks a name into lines that fit the seal on screen.
func wrapForScreen(text string, size float32, style fyne.TextStyle, width float32) []string {
	words := strings.Fields(text)
	if len(words) == 0 || size <= 0 {
		return nil
	}
	var lines []string
	current := words[0]
	for _, word := range words[1:] {
		candidate := current + " " + word
		if fyne.MeasureText(candidate, size, style).Width <= width {
			current = candidate
			continue
		}
		lines = append(lines, current)
		current = word
	}
	return append(lines, current)
}

func place(object fyne.CanvasObject, x, y, width, height float64) {
	object.Move(fyne.NewPos(float32(x), float32(y)))
	object.Resize(fyne.NewSize(float32(width), float32(height)))
}

// MinSize defers to the widget.
func (r *pageCanvasRenderer) MinSize() fyne.Size { return r.canvas.MinSize() }

// Refresh re-applies the state-dependent colours, then lays out again.
func (r *pageCanvasRenderer) Refresh() {
	r.applyState()
	r.Layout(r.canvas.Size())
	canvas.Refresh(r.canvas)
}

// applyState colours the frame by what the seal covers and shows the focus
// ring when the keyboard is on the canvas.
func (r *pageCanvasRenderer) applyState() {
	p := r.canvas
	r.paper.Image = p.page

	r.frame.StrokeColor = sealInk
	if p.CoversText() {
		r.frame.StrokeColor = sealWarning
	}
	r.focusRing.StrokeColor = color.Transparent
	if p.focused {
		r.focusRing.StrokeColor = DefaultPalette().Accent
	}
}

// Objects lists what is drawn, back to front.
func (r *pageCanvasRenderer) Objects() []fyne.CanvasObject {
	r.objects = append(r.objects[:0], r.shadow, r.paper, r.veil, r.rubric, r.bar)
	for _, line := range r.lines {
		r.objects = append(r.objects, line)
	}
	return append(r.objects, r.frame, r.focusRing, r.handle)
}

// Destroy is a no-op: Fyne owns the objects.
func (r *pageCanvasRenderer) Destroy() {}

// compile-time checks: the canvas must answer every input it promises.
var (
	_ fyne.Tappable      = (*PageCanvas)(nil)
	_ fyne.Draggable     = (*PageCanvas)(nil)
	_ fyne.Focusable     = (*PageCanvas)(nil)
	_ desktop.Hoverable  = (*PageCanvas)(nil)
	_ desktop.Cursorable = (*PageCanvas)(nil)
	_ fyne.Accessible    = (*PageCanvas)(nil)
)
