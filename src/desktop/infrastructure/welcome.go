//go:build gui

package infrastructure

import (
	"bytes"
	"image"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/anvius/trebaruna/src/desktop/messaging"
)

// WelcomeScreen is the first thing the user sees.
//
// It exists because a signature tool is opened rarely and by people who are not
// experts: a blank form with ten fields is intimidating. The screen states what
// the program does, in three lines, and offers a single action.
type WelcomeScreen struct {
	window   fyne.Window
	palette  Palette
	messages messaging.Catalogue
	// onStart swaps the window content for the working form.
	onStart func()
}

// NewWelcomeScreen builds the cover.
func NewWelcomeScreen(window fyne.Window, palette Palette, messages messaging.Catalogue, onStart func()) *WelcomeScreen {
	return &WelcomeScreen{window: window, palette: palette, messages: messages, onStart: onStart}
}

// CanvasObject returns the cover, ready to be set as window content.
func (s *WelcomeScreen) CanvasObject() fyne.CanvasObject {
	m := s.messages

	// The logo is scaled to 160 px: big enough to carry the identity, small
	// enough to leave the claim and the button above the fold.
	logo := canvas.NewImageFromImage(decodeIcon())
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(160, 160))
	logoContainer := container.NewCenter(logo)

	title := canvas.NewText(m.WelcomeTitle, s.palette.Text)
	title.TextSize = 34
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	tagline := widget.NewLabel(m.WelcomeTagline)
	tagline.Alignment = fyne.TextAlignCenter
	tagline.Wrapping = fyne.TextWrapWord

	points := widget.NewLabel(m.WelcomePoint1 + "\n" + m.WelcomePoint2 + "\n" + m.WelcomePoint3)
	points.Alignment = fyne.TextAlignLeading
	points.Wrapping = fyne.TextWrapWord

	start := widget.NewButtonWithIcon(m.WelcomeStart, theme.ConfirmIcon(), func() {
		if s.onStart != nil {
			s.onStart()
		}
	})
	start.Importance = widget.HighImportance

	// A fixed-width column keeps the text readable instead of stretching lines
	// across a 1200 px window, which is the classic centred-layout mistake.
	column := container.NewVBox(
		container.NewCenter(title),
		container.NewCenter(tagline),
		widget.NewSeparator(),
		container.NewCenter(points),
		widget.NewSeparator(),
		start,
	)

	return container.NewCenter(
		container.NewVBox(
			logoContainer,
			container.NewPadded(column),
		),
	)
}

// decodeIcon turns the embedded PNG into an image, returning nil if it fails:
// a missing logo must not prevent signing a document.
func decodeIcon() image.Image {
	decoded, _, err := image.Decode(bytes.NewReader(appIconPNG))
	if err != nil {
		return nil
	}
	return decoded
}
