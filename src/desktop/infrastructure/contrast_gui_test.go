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
// dialogs), in the dark palette and in the light one.
func TestEveryTextColourReadsOnEverySurface(t *testing.T) {
	for palette, variant := range map[string]fyne.ThemeVariant{"dark": theme.VariantDark, "light": theme.VariantLight} {
		app := NewAppTheme(PaletteFor(variant))
		colour := func(name fyne.ThemeColorName) color.Color { return app.Color(name, variant) }
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
					t.Errorf("%s: %s on the %s: %.2f:1, want %.1f:1", palette, name, surface, got, want)
				}
			}
		}
		if got := contrast(colour(theme.ColorNameForegroundOnPrimary), colour(theme.ColorNamePrimary)); got < 4.5 {
			t.Errorf("%s: text on a primary button: %.2f:1", palette, got)
		}
	}
}

// TestThePaletteFollowsTheDesktop: a light desktop gets the light palette,
// any other the dark one; the colours the theme leaves to Fyne come in the
// palette's variant, whatever variant Fyne asks for later, so a desktop that
// changes its preference while the app runs does not mix the two.
func TestThePaletteFollowsTheDesktop(t *testing.T) {
	if PaletteFor(theme.VariantLight).Variant != theme.VariantLight || PaletteFor(theme.VariantDark).Variant != theme.VariantDark {
		t.Fatal("the palette does not follow the desktop's variant")
	}
	if luminance(PaletteFor(theme.VariantLight).Background) < luminance(PaletteFor(theme.VariantLight).Text) {
		t.Error("the light palette has dark text on a light background")
	}
	dark := NewAppTheme(DefaultPalette())
	want := theme.DefaultTheme().Color(theme.ColorNameHeaderBackground, theme.VariantDark)
	if got := dark.Color(theme.ColorNameHeaderBackground, theme.VariantLight); got != want {
		t.Errorf("a colour left to Fyne: %v, want the dark variant's %v", got, want)
	}
}
