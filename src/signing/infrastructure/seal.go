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

import (
	"fmt"
	"time"

	"codeberg.org/anvius/pignus/src/signing/domain/identity"
	"github.com/digitorus/pdfsign"
)

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
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("seal dimensions must be positive, got %.1fx%.1f pt", width, height)
	}

	typography := typographyFor(width, height)
	appearance := pdfsign.NewAppearance(width, height)

	innerWidth := width - 2*typography.padding
	if innerWidth < 20 {
		return nil, fmt.Errorf("seal %.0f pt wide leaves no room for text", width)
	}

	nameLines := wrapToWidth(holder.Name, innerWidth, typography.nameSize, true)
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

	drawAccentBar(appearance, width, height)
	drawName(appearance, nameLines, typography, height, totalHeight)
	drawDetails(appearance, details, typography, height, totalHeight)

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
		if textWidth(combined, typography.detailSize, false) <= width {
			details = append(details, combined)
		} else {
			details = append(details, wrapToWidth(holder.Identifier, width, typography.detailSize, false)...)
			details = append(details, date)
		}
	default:
		details = append(details, date)
	}

	// The time keeps its offset: without it a reader cannot tell whether the
	// stamp refers to UTC or to the signer's desk.
	details = append(details, wrapToWidth(clock, width, typography.timeSize, false)...)
	return details, nil
}

// drawAccentBar paints the vertical rule that anchors the block.
func drawAccentBar(appearance *pdfsign.Appearance, width, height float64) {
	const barWidth = 1.8
	const inset = 1.2

	appearance.
		DrawRect(inset, inset, barWidth, height-2*inset).
		Fill(38, 84, 124)
}

// drawName renders the bold name, top-aligned.
func drawName(appearance *pdfsign.Appearance, lines []string, typography sealTypography, height, totalHeight float64) {
	bold := pdfsign.StandardFont(pdfsign.HelveticaBold)

	// The block is vertically centred, which keeps small seals from looking
	// top-heavy and large ones from floating.
	top := (height - totalHeight) / 2
	baseline := height - top - typography.nameSize

	for _, line := range lines {
		appearance.Text(line).
			Font(bold, typography.nameSize).
			Position(typography.padding+3.2, baseline).
			SetColor(16, 20, 26)
		baseline -= typography.leading
	}
}

// drawDetails renders the identifier, date and time in grey.
func drawDetails(appearance *pdfsign.Appearance, lines []string, typography sealTypography, height, totalHeight float64) {
	regular := pdfsign.StandardFont(pdfsign.Helvetica)

	top := (height - totalHeight) / 2
	baseline := height - top - typography.nameSize - typography.gapAfterName - typography.detailSize

	for index, line := range lines {
		size := typography.detailSize
		if index == len(lines)-1 {
			// The time line is the least important: slightly smaller.
			size = typography.timeSize
		}
		appearance.Text(line).
			Font(regular, size).
			Position(typography.padding+3.2, baseline).
			SetColor(78, 86, 96)
		baseline -= typography.leading
	}
}
