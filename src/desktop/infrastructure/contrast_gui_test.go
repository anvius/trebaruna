//go:build gui

package infrastructure

import (
	"image/color"
	"math"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// luminance is a colour's relative luminance (WCAG 2.2).
func luminance(c color.Color) float64 {
	r, g, b, _ := c.RGBA()
	channel := func(value uint32) float64 {
		v := float64(value) / 0xFFFF
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(r) + 0.7152*channel(g) + 0.0722*channel(b)
}

func contrast(a, b color.Color) float64 {
	high, low := luminance(a), luminance(b)
	if low > high {
		high, low = low, high
	}
	return (high + 0.05) / (low + 0.05)
}

// TestEveryTextColourReadsOnEverySurface: WCAG 2.2 AA, 4.5:1 for text
// (1.4.3) and 3:1 for the edges of controls and the focus ring (1.4.11),
// on the window, the fields and the raised surfaces (buttons, menus,
// dialogs).
func TestEveryTextColourReadsOnEverySurface(t *testing.T) {
	app := NewAppTheme(DefaultPalette())
	colour := func(name fyne.ThemeColorName) color.Color { return app.Color(name, theme.VariantDark) }
	surfaces := map[string]color.Color{
		"background": colour(theme.ColorNameBackground), "field": colour(theme.ColorNameInputBackground),
		"button": colour(theme.ColorNameButton), "dialog": colour(theme.ColorNameOverlayBackground),
	}
	for name, want := range map[fyne.ThemeColorName]float64{
		theme.ColorNameForeground: 4.5, theme.ColorNamePlaceHolder: 4.5, theme.ColorNameDisabled: 4.5,
		theme.ColorNamePrimary: 4.5, theme.ColorNameError: 4.5, theme.ColorNameWarning: 4.5, theme.ColorNameSuccess: 4.5,
		theme.ColorNameInputBorder: 3, theme.ColorNameFocus: 3,
	} {
		for surface, background := range surfaces {
			if got := contrast(colour(name), background); got < want {
				t.Errorf("%s on the %s: %.2f:1, want %.1f:1", name, surface, got, want)
			}
		}
	}
	if got := contrast(colour(theme.ColorNameForegroundOnPrimary), colour(theme.ColorNamePrimary)); got < 4.5 {
		t.Errorf("text on a primary button: %.2f:1", got)
	}
}
