//go:build gui

package infrastructure

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

// namedButton is an icon button with a name a screen reader can say: a
// plain icon button is announced by its icon's file name.
type namedButton struct {
	widget.Button
	name string
}

func newNamedButton(name string, icon fyne.Resource, tapped func()) *namedButton {
	button := &namedButton{name: name}
	button.Icon, button.OnTapped = icon, tapped
	button.ExtendBaseWidget(button)
	return button
}

// AccessibilityLabel is the button's name.
func (b *namedButton) AccessibilityLabel() string { return b.name }

var _ fyne.Accessible = (*namedButton)(nil)
