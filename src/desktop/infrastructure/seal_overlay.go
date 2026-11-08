//go:build gui

package infrastructure

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/anvius/pignus/src/desktop/domain"
)

// SealOverlay is the draggable rectangle that sits on top of the page preview.
//
// It owns no signature logic: it reports a rectangle in PDF points and lets the
// window decide what to do with it. Dragging, clamping and the on-page look live
// here because they are presentation concerns.
type SealOverlay struct {
	widget.BaseWidget

	geometry domain.PageGeometry
	rect     domain.SealRect
	// displayScale converts PDF points into canvas pixels, which depends on the
	// size the page image is drawn at on screen.
	displayScale float64
	// onChange is called after every significant move so the window can update
	// the box field and the preview.
	onChange func(domain.SealRect)

	background *canvas.Rectangle
	label      *canvas.Text
	handle     *canvas.Rectangle
}

// SealOverlayStyle groups the visual constants of the overlay.
type SealOverlayStyle struct {
	Fill   color.Color
	Border color.Color
	Handle color.Color
	Text   color.Color
}

// DefaultSealOverlayStyle is a red outline with a translucent fill: it has to be
// unmistakable over black text without hiding what is underneath.
func DefaultSealOverlayStyle() SealOverlayStyle {
	return SealOverlayStyle{
		Fill:   color.NRGBA{R: 214, G: 64, B: 69, A: 44},
		Border: color.NRGBA{R: 214, G: 64, B: 69, A: 255},
		Handle: color.NRGBA{R: 214, G: 64, B: 69, A: 255},
		Text:   color.NRGBA{R: 120, G: 20, B: 24, A: 255},
	}
}

// NewSealOverlay builds the overlay for one page.
func NewSealOverlay(geometry domain.PageGeometry, rect domain.SealRect, displayScale float64, onChange func(domain.SealRect)) *SealOverlay {
	style := DefaultSealOverlayStyle()

	overlay := &SealOverlay{
		geometry:     geometry,
		rect:         geometry.Clamp(rect),
		displayScale: displayScale,
		onChange:     onChange,
		background:   canvas.NewRectangle(style.Fill),
		label:        canvas.NewText("", style.Text),
		handle:       canvas.NewRectangle(style.Handle),
	}
	overlay.label.TextSize = 11
	overlay.label.TextStyle = fyne.TextStyle{Bold: true}

	overlay.ExtendBaseWidget(overlay)
	return overlay
}

// Dragged moves the seal with the pointer.
func (o *SealOverlay) Dragged(event *fyne.DragEvent) {
	if o.displayScale <= 0 {
		return
	}

	deltaX := float64(event.Dragged.DX) / o.displayScale
	// Canvas Y grows downwards and PDF Y grows upwards, so the vertical delta is
	// inverted. Without this the seal runs away from the pointer.
	deltaY := -float64(event.Dragged.DY) / o.displayScale

	o.rect = o.geometry.Clamp(o.rect.MoveBy(deltaX, deltaY))
	o.notify()
	o.Refresh()
}

// DragEnd finalises the move.
func (o *SealOverlay) DragEnd() { o.notify() }

// Cursor shows a crosshair over the seal, so the affordance is obvious.
func (o *SealOverlay) Cursor() desktop.Cursor { return desktop.CrosshairCursor }

// Rect returns the current seal rectangle in PDF points.
func (o *SealOverlay) Rect() domain.SealRect { return o.rect }

// SetRect replaces the rectangle, usually after a suggestion is picked or a
// numeric edit happens.
func (o *SealOverlay) SetRect(rect domain.SealRect) {
	o.rect = o.geometry.Clamp(rect)
	o.notify()
	o.Refresh()
}

// SetDisplayScale updates the points-to-pixels factor when the image resizes.
func (o *SealOverlay) SetDisplayScale(scale float64) {
	if scale <= 0 {
		return
	}
	o.displayScale = scale
	o.Refresh()
}

// SetLabel sets the caption drawn inside the seal.
func (o *SealOverlay) SetLabel(text string) {
	o.label.Text = text
	o.label.Refresh()
}

// notify reports the rectangle to the owner.
func (o *SealOverlay) notify() {
	if o.onChange != nil {
		o.onChange(o.rect)
	}
}

// CreateRenderer builds the canvas objects.
func (o *SealOverlay) CreateRenderer() fyne.WidgetRenderer {
	style := DefaultSealOverlayStyle()

	// A single stroked rectangle reads as a frame with a translucent fill,
	// instead of four separate bars.
	frame := canvas.NewRectangle(color.Transparent)
	frame.StrokeColor = style.Border
	frame.StrokeWidth = 2

	return &sealOverlayRenderer{
		overlay: o,
		objects: []fyne.CanvasObject{o.background, frame, o.handle, o.label},
		frame:   frame,
	}
}

// sealOverlayRenderer draws the overlay.
type sealOverlayRenderer struct {
	overlay *SealOverlay
	objects []fyne.CanvasObject
	frame   *canvas.Rectangle
}

// Layout positions the objects from the current rectangle.
func (r *sealOverlayRenderer) Layout(size fyne.Size) {
	o := r.overlay
	if o.displayScale <= 0 {
		return
	}

	width := float32(o.rect.Width() * o.displayScale)
	height := float32(o.rect.Height() * o.displayScale)
	// Canvas origin is top-left; PDF origin is bottom-left.
	x := float32(o.rect.LowerLeftX * o.displayScale)
	y := float32((o.geometry.HeightPoints - o.rect.UpperRightY) * o.displayScale)

	o.background.Resize(fyne.NewSize(width, height))
	o.background.Move(fyne.NewPos(x, y))

	r.frame.Resize(fyne.NewSize(width, height))
	r.frame.Move(fyne.NewPos(x, y))

	o.handle.Resize(fyne.NewSize(10, 10))
	o.handle.Move(fyne.NewPos(x+width-10, y+height-10))

	o.label.Move(fyne.NewPos(x+6, y+4))
}

// MinSize is the smallest useful overlay.
func (r *sealOverlayRenderer) MinSize() fyne.Size {
	return fyne.NewSize(20, 20)
}

// Refresh redraws every child.
func (r *sealOverlayRenderer) Refresh() {
	r.overlay.background.Refresh()
	r.frame.Refresh()
	r.overlay.handle.Refresh()
	r.overlay.label.Refresh()
}

// Objects returns the canvas children.
func (r *sealOverlayRenderer) Objects() []fyne.CanvasObject { return r.objects }

// Destroy is a no-op: Fyne owns the objects.
func (r *sealOverlayRenderer) Destroy() {}
