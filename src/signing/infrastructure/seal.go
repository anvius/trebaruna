package infrastructure

// The seal is the only part of a signature a human actually looks at, so it is
// designed rather than dumped:
//
//	┌──────────────────────────────┐
//	│ ▌MARIA LOPEZ GARCIA          │  bold, wrapped, never truncated
//	│  MARTINEZ                    │
//	│  00000000X · 02/11/2026      │  identifier and date, one line
//	│  14:05:09 +01:00             │  time with the offset made explicit
//	└──────────────────────────────┘
//
// Choices and their reasons:
//
//   - Helvetica, not Courier. A monospaced face reads as a terminal dump; the
//     base-14 sans face is what every commercial signer uses and it is present
//     in every PDF reader without embedding.
//   - Three type sizes, not one. The name carries the identity; the rest is
//     supporting detail. A single size makes the block flat and hard to scan.
//   - A quiet accent bar on the left, not a heavy frame. A thick border fights
//     with the page; a 2 pt rule anchors the block and disappears on photocopy.
//   - Date and time on separate lines only when the width demands it. Cramming
//     them onto one line in a narrow box produced "2026-11-02" split as
//     "2026-" / "11-02", which is unreadable.
//   - No logos. A signature mark that can carry arbitrary artwork is a mark
//     that can be spoofed; the identity comes from the certificate.
//   - A rubric, the image of a handwritten signature, goes to the left of the
//     data, never alone and never over them (ADR-0012):
//
//	┌──────────────────────────────────────┐
//	│  ╭~~~~~~~~~╮  ▌MARIA LOPEZ GARCIA     │
//	│  ╰~~~~~~~~~╯   00000000X · 02/11/2026 │
//	│                14:05:09 +01:00        │
//	└──────────────────────────────────────┘
//
//     It takes at most half the width, its proportions kept; the data keep
//     the type size they have without it, and a box too narrow for both is
//     refused.

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/domain/identity"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/helvetica"
	"github.com/digitorus/pdfsign"
)

// textIndent is the room the accent rule takes before the text, beyond the
// padding.
const textIndent = 3.2

// sealTypography holds the type scale for the stamp, in points.
type sealTypography struct {
	// padding is the inner margin on every side.
	padding float64
	// nameSize is the signer's name.
	nameSize float64
	// detailSize is used for the identifier and the date.
	detailSize float64
	// timeSize is used for the time line.
	timeSize float64
	// leading is the distance between baselines.
	leading float64
	// gapAfterName separates the name block from the details.
	gapAfterName float64
}

// typographyFor scales the type to the box, so a small seal stays legible and a
// large one does not look sparse.
func typographyFor(width, height float64) sealTypography {
	// The height drives the scale: three text lines plus padding must fit.
	scale := height / 48.0
	if width < height*1.2 {
		// Near-square boxes get slightly smaller type to keep the line length
		// reasonable; otherwise every word wraps.
		scale *= 0.92
	}

	typography := sealTypography{
		padding:      2.6,
		nameSize:     5.6 * scale,
		detailSize:   4.6 * scale,
		timeSize:     4.4 * scale,
		leading:      5.4 * scale,
		gapAfterName: 1.6 * scale,
	}

	// Clamp so an unusually large seal does not turn into a poster.
	if typography.nameSize > 11 {
		factor := 11 / typography.nameSize
		typography.nameSize *= factor
		typography.detailSize *= factor
		typography.timeSize *= factor
		typography.leading *= factor
		typography.gapAfterName *= factor
	}
	return typography
}

// DrawSeal composes the stamp.
//
// Every value comes from the certificate except the moment. If the identity does
// not fit, this returns an error: a signature mark that silently drops a surname
// is worse than a refusal, because the user cannot tell it happened.
func DrawSeal(width, height float64, holder identity.Holder, moment time.Time) (*pdfsign.Appearance, error) {
	return DrawSealWithRubric(width, height, holder, moment, domain.Rubric{})
}

// DrawSealWithRubric composes the stamp with a rubric to the left of the
// certificate data; with none, it is DrawSeal.
func DrawSealWithRubric(width, height float64, holder identity.Holder, moment time.Time, rubric domain.Rubric) (*pdfsign.Appearance, error) {
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("seal dimensions must be positive, got %.1fx%.1f pt", width, height)
	}

	// The type is sized by the whole box, rubric or not: the data keep their
	// size and the rubric takes room beside them.
	typography := typographyFor(width, height)
	appearance := pdfsign.NewAppearance(width, height)

	// left is where the data block starts: the box's edge, or past the rubric.
	left := 0.0
	if !rubric.IsZero() {
		var err error
		if left, err = drawRubric(appearance, rubric, width, height, typography.padding); err != nil {
			return nil, err
		}
	}

	// The text starts after the accent rule and ends at the right padding:
	// wrapping it to the box minus both paddings let a full line run past
	// the edge.
	innerWidth := width - left - textIndent - 2*typography.padding
	switch {
	case innerWidth < 20 && !rubric.IsZero():
		return nil, fmt.Errorf("seal %.0f pt wide leaves no room for the certificate data beside the rubric: widen it", width)
	case innerWidth < 20:
		return nil, fmt.Errorf("seal %.0f pt wide leaves no room for text", width)
	}

	nameLines := helvetica.Wrap(holder.Name, innerWidth, typography.nameSize, true)
	if len(nameLines) == 0 {
		return nil, fmt.Errorf("the certificate carries no printable name")
	}

	details, err := sealDetailLines(holder, moment, innerWidth, typography)
	if err != nil {
		return nil, err
	}

	totalHeight := float64(len(nameLines))*typography.leading +
		typography.gapAfterName +
		float64(len(details))*typography.leading

	if totalHeight+2*typography.padding > height {
		return nil, fmt.Errorf(
			"certificate identity needs %.1f pt of height but the seal offers %.1f pt; "+
				"enlarge the box instead of truncating the identity",
			totalHeight+2*typography.padding, height,
		)
	}

	drawAccentBar(appearance, left, height)
	drawName(appearance, nameLines, typography, left, height, totalHeight)
	drawDetails(appearance, details, len(nameLines), typography, left, height, totalHeight)

	return appearance, nil
}

// sealDetailLines builds the supporting lines: identifier and date, then time.
func sealDetailLines(holder identity.Holder, moment time.Time, width float64, typography sealTypography) ([]string, error) {
	date := moment.Format("02/01/2006")
	clock := moment.Format("15:04:05 -07:00")

	var details []string
	switch {
	case holder.Identifier != "":
		// Identifier and date together when they fit: fewer lines means a
		// tighter block, and the identifier is what a verifier looks for.
		combined := holder.Identifier + " · " + date
		if helvetica.Width(combined, typography.detailSize, false) <= width {
			details = append(details, combined)
		} else {
			details = append(details, helvetica.Wrap(holder.Identifier, width, typography.detailSize, false)...)
			details = append(details, date)
		}
	default:
		details = append(details, date)
	}

	// The time keeps its offset: without it a reader cannot tell whether the
	// stamp refers to UTC or to the signer's desk.
	details = append(details, helvetica.Wrap(clock, width, typography.timeSize, false)...)
	return details, nil
}

// drawAccentBar paints the vertical rule that anchors the block.
//
// It is a thick line, not a filled rectangle: pdfsign v1.0.0 registers
// DrawRect as a builder type its renderer does not draw, so the rectangle was
// silently dropped from every seal. Width must come before Stroke, which is
// the call that commits the line.
func drawAccentBar(appearance *pdfsign.Appearance, left, height float64) {
	const barWidth = 1.8
	const inset = 1.2

	x := left + inset + barWidth/2
	appearance.
		Line(x, inset, x, height-inset).
		Width(barWidth).
		Stroke(38, 84, 124)
}

// drawName renders the bold name, top-aligned.
func drawName(appearance *pdfsign.Appearance, lines []string, typography sealTypography, left, height, totalHeight float64) {
	bold := pdfsign.StandardFont(pdfsign.HelveticaBold)

	// The block is vertically centred, which keeps small seals from looking
	// top-heavy and large ones from floating.
	top := (height - totalHeight) / 2
	baseline := height - top - typography.nameSize

	for _, line := range lines {
		// The colour goes before Position, which commits the element: set
		// after it, the colour was lost and the line printed pure black.
		appearance.Text(line).
			Font(bold, typography.nameSize).
			SetColor(16, 20, 26).
			Position(left+typography.padding+textIndent, baseline)
		baseline -= typography.leading
	}
}

// drawDetails renders the identifier, date and time in grey, below the last
// line of the name: a name that wraps pushes the details down with it.
func drawDetails(appearance *pdfsign.Appearance, lines []string, nameLines int, typography sealTypography, left, height, totalHeight float64) {
	regular := pdfsign.StandardFont(pdfsign.Helvetica)

	top := (height - totalHeight) / 2
	lastName := height - top - typography.nameSize - float64(nameLines-1)*typography.leading
	baseline := lastName - typography.gapAfterName - typography.detailSize

	for index, line := range lines {
		size := typography.detailSize
		if index == len(lines)-1 {
			// The time line is the least important: slightly smaller.
			size = typography.timeSize
		}
		appearance.Text(line).
			Font(regular, size).
			SetColor(78, 86, 96).
			Position(left+typography.padding+textIndent, baseline)
		baseline -= typography.leading
	}
}

// drawRubric places the rubric where the domain's rule puts it and returns
// where the data block starts.
func drawRubric(appearance *pdfsign.Appearance, rubric domain.Rubric, width, height, padding float64) (float64, error) {
	box, dataLeft, ok := rubric.Fit(width, height, padding)
	if !ok {
		return 0, fmt.Errorf("seal %.0fx%.0f pt leaves no room for a rubric", width, height)
	}
	data, err := rubricForPDF(rubric.Content())
	if err != nil {
		return 0, err
	}
	appearance.Image(&pdfsign.Image{Name: "rubric", Data: data}).
		Rect(box.X, box.Y, box.Width, box.Height).
		ScaleStretch()
	return dataLeft, nil
}

// rubricForPDF hands pdfsign an image it embeds correctly. It copies a JPEG
// as is under /DeviceRGB, which only holds for a colour (YCbCr) JPEG: a
// greyscale or CMYK one is re-encoded as PNG, which pdfsign writes pixel by
// pixel. PNGs pass through, their transparency kept.
func rubricForPDF(content []byte) ([]byte, error) {
	config, format, err := image.DecodeConfig(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("read the rubric: %w", err)
	}
	if format != "jpeg" || config.ColorModel == color.YCbCrModel {
		return content, nil
	}
	decoded, _, err := image.Decode(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("read the rubric: %w", err)
	}
	var converted bytes.Buffer
	if err := png.Encode(&converted, decoded); err != nil {
		return nil, fmt.Errorf("convert the rubric: %w", err)
	}
	return converted.Bytes(), nil
}
