//go:build gui

package infrastructure

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Palette is the application's visual identity.
//
// The colours are chosen for a signature tool, not for a consumer app: a deep
// slate background that makes a white page pop, a single accent used only for
// the primary action and the seal, and text contrast above 7:1 so the dense
// form stays readable in a dim office.
type Palette struct {
	Background    color.Color
	Surface       color.Color
	SurfaceRaised color.Color
	// Desk is the field the page preview lies on: darker than the paper in
	// either palette, so the sheet stands out.
	Desk        color.Color
	Accent      color.Color
	AccentMuted color.Color
	Danger      color.Color
	Warning     color.Color
	Success     color.Color
	Text        color.Color
	TextMuted   color.Color
	Border      color.Color
	// Outline draws the edge of a field: it must stand out from the
	// background (WCAG 1.4.11), unlike a decorative Border.
	Outline color.Color
	Overlay color.Color
	// Variant is the Fyne variant the palette belongs to: the colours this
	// theme does not answer come from Fyne's default theme in that variant.
	Variant fyne.ThemeVariant
}

// DefaultPalette is the shipped identity.
func DefaultPalette() Palette {
	return Palette{
		// A blue slate rather than a neutral grey: the desk under a sheet of
		// paper, and the same family as the seal's ink.
		Background:    color.NRGBA{R: 26, G: 32, B: 43, A: 255},
		Surface:       color.NRGBA{R: 34, G: 42, B: 55, A: 255},
		SurfaceRaised: color.NRGBA{R: 43, G: 53, B: 69, A: 255},
		Desk:          color.NRGBA{R: 34, G: 42, B: 55, A: 255},
		// A muted teal: reads as "official document" rather than as a warning.
		// Accent and Danger are as dark as WCAG AA allows on every surface
		// (4.5:1 for text, raised surfaces included).
		Accent:      color.NRGBA{R: 66, G: 173, B: 169, A: 255},
		AccentMuted: color.NRGBA{R: 66, G: 173, B: 169, A: 70},
		Danger:      color.NRGBA{R: 235, G: 125, B: 121, A: 255},
		Warning:     color.NRGBA{R: 226, G: 170, B: 84, A: 255},
		Success:     color.NRGBA{R: 110, G: 196, B: 128, A: 255},
		Text:        color.NRGBA{R: 236, G: 240, B: 245, A: 255},
		TextMuted:   color.NRGBA{R: 160, G: 172, B: 188, A: 255},
		Border:      color.NRGBA{R: 58, G: 70, B: 88, A: 255},
		Outline:     color.NRGBA{R: 118, G: 130, B: 146, A: 255},
		Overlay:     color.NRGBA{R: 0, G: 0, B: 0, A: 160},
		Variant:     theme.VariantDark,
	}
}

// LightPalette is the identity on a light desktop: a pale grey window with
// white fields, and the teal and the signal colours darkened until they keep,
// on every light surface, the contrast the dark palette keeps on its own.
func LightPalette() Palette {
	return Palette{
		Background:    color.NRGBA{R: 238, G: 241, B: 245, A: 255},
		Surface:       color.NRGBA{R: 255, G: 255, B: 255, A: 255},
		SurfaceRaised: color.NRGBA{R: 225, G: 230, B: 237, A: 255},
		Desk:          color.NRGBA{R: 208, G: 214, B: 223, A: 255},
		Accent:        color.NRGBA{R: 11, G: 107, B: 103, A: 255},
		AccentMuted:   color.NRGBA{R: 11, G: 107, B: 103, A: 50},
		Danger:        color.NRGBA{R: 176, G: 38, B: 32, A: 255},
		Warning:       color.NRGBA{R: 138, G: 83, B: 0, A: 255},
		Success:       color.NRGBA{R: 37, G: 107, B: 41, A: 255},
		Text:          color.NRGBA{R: 23, G: 32, B: 43, A: 255},
		TextMuted:     color.NRGBA{R: 74, G: 86, B: 104, A: 255},
		Border:        color.NRGBA{R: 197, G: 205, B: 216, A: 255},
		Outline:       color.NRGBA{R: 107, G: 118, B: 134, A: 255},
		Overlay:       color.NRGBA{R: 0, G: 0, B: 0, A: 90},
		Variant:       theme.VariantLight,
	}
}

// PaletteFor is the palette for the desktop's preference: the light one on
// a light desktop, the shipped dark one otherwise.
func PaletteFor(variant fyne.ThemeVariant) Palette {
	if variant == theme.VariantLight {
		return LightPalette()
	}
	return DefaultPalette()
}

// useTheme themes the app after the desktop's preference (FYNE_THEME=light
// or dark overrides it). It is chosen once, when the app starts: the
// window's own drawings take their colours when built, so a change of
// preference applies on the next start.
func useTheme(fyneApp fyne.App) {
	fyneApp.Settings().SetTheme(NewAppTheme(PaletteFor(fyneApp.Settings().ThemeVariant())))
}

// currentPalette is the palette of the app's theme, the dark one when the
// app has another theme (as in tests).
func currentPalette() Palette {
	if applied, ok := fyne.CurrentApp().Settings().Theme().(*AppTheme); ok {
		return applied.palette
	}
	return DefaultPalette()
}

// AppTheme applies the palette to every Fyne widget.
//
// Implementing fyne.Theme means no widget keeps the default look: a half-themed
// window looks worse than an unthemed one, which is why every colour name and
// size the app can reach is answered here.
type AppTheme struct {
	palette Palette
	// base supplies anything this theme does not override, so future Fyne
	// widgets keep working instead of rendering with zero values.
	base fyne.Theme
}

// NewAppTheme builds the theme.
func NewAppTheme(palette Palette) *AppTheme {
	return &AppTheme{palette: palette, base: theme.DefaultTheme()}
}

// Color answers every theme colour the app can request.
func (t *AppTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	p := t.palette

	switch name {
	case theme.ColorNameBackground:
		return p.Background
	case theme.ColorNameOverlayBackground:
		return p.SurfaceRaised
	case theme.ColorNameMenuBackground:
		return p.SurfaceRaised
	case theme.ColorNameInputBackground:
		return p.Surface
	case theme.ColorNameButton:
		return p.SurfaceRaised
	case theme.ColorNamePrimary:
		return p.Accent
	case theme.ColorNameForeground:
		return p.Text
	case theme.ColorNameForegroundOnPrimary:
		return p.Background
	case theme.ColorNamePlaceHolder:
		return p.TextMuted
	case theme.ColorNameDisabled:
		return p.TextMuted
	case theme.ColorNameDisabledButton:
		return p.Surface
	case theme.ColorNameError:
		return p.Danger
	case theme.ColorNameSuccess:
		return p.Success
	case theme.ColorNameWarning:
		return p.Warning
	case theme.ColorNameHover:
		return p.AccentMuted
	case theme.ColorNameFocus:
		return p.Accent
	case theme.ColorNameSelection:
		return p.AccentMuted
	case theme.ColorNameSeparator:
		return p.Border
	case theme.ColorNameInputBorder:
		return p.Outline
	case theme.ColorNameShadow:
		return p.Overlay
	case theme.ColorNameScrollBar:
		return p.Border
	case theme.ColorNameScrollBarBackground:
		return p.Background
	}

	return t.base.Color(name, p.Variant)
}

// Font returns the default typeface; the app does not ship custom fonts, so
// text stays legible at every DPI instead of depending on a bundled file.
func (t *AppTheme) Font(style fyne.TextStyle) fyne.Resource {
	return t.base.Font(style)
}

// Icon falls back to the default set.
func (t *AppTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.base.Icon(name)
}

// Size tunes spacing and type scale.
//
// Generous spacing is deliberate: this form is filled once, under time pressure,
// usually with a document at hand. Cramped inputs cause mistakes.
func (t *AppTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 10
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 22
	case theme.SizeNameSubHeadingText:
		return 17
	case theme.SizeNameCaptionText:
		return 12
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameInputRadius:
		return 6
	case theme.SizeNameSelectionRadius:
		return 4
	case theme.SizeNameScrollBar:
		return 12
	}
	return t.base.Size(name)
}

// compile-time check.
var _ fyne.Theme = (*AppTheme)(nil)
