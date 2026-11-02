package infrastructure

import (
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"codeberg.org/simplicer/firma-it/src/signing/domain/identity"
	"github.com/digitorus/pdfsign"
)

// DrawSeal prints the complete identity and an explicitly zoned local time.
// A compact appearance is a presentation choice, not an ETSI size requirement.
func DrawSeal(width, height float64, holder identity.Holder, moment time.Time) (*pdfsign.Appearance, error) {
	const padding = 3.0
	// Courier has a fixed 0.6em advance: wrapping is deterministic, including
	// long fiscal identifiers, without trusting approximate glyph widths.
	const fontSize = 5.0
	columns := int(math.Floor((width - 2*padding) / (0.6 * fontSize)))
	if columns < 8 {
		return nil, fmt.Errorf("seal is too narrow for readable certificate text")
	}
	lines := wrapSealText(holder.Name, columns)
	lines = append(lines, wrapSealText(holder.Identifier, columns)...)
	lines = append(lines, moment.Format("2006-01-02"), moment.Format("15:04:05 -07:00"))
	const leading = 6.0
	if float64(len(lines))*leading+2*padding > height {
		return nil, fmt.Errorf("certificate identity needs a larger seal than %.0fx%.0f pt; text will not be truncated", width, height)
	}
	appearance := pdfsign.NewAppearance(width, height)
	appearance.Border(0.5, 50, 65, 75)
	font := pdfsign.StandardFont(pdfsign.Courier)
	for i, line := range lines {
		appearance.Text(line).Font(font, fontSize).Position(padding, padding+float64(i)*leading).SetColor(20, 24, 28)
	}
	return appearance, nil
}

// wrapSealText preserves every character, splitting long tokens when necessary.
func wrapSealText(text string, columns int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) <= columns {
			line += " " + word
			continue
		}
		if line != "" {
			lines = append(lines, line)
			line = ""
		}
		runes := []rune(word)
		for len(runes) > columns {
			lines = append(lines, string(runes[:columns]))
			runes = runes[columns:]
		}
		line = string(runes)
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
