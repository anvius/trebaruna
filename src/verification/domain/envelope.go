package domain

import (
	"path/filepath"
	"strings"
)

// ExtractedDocument is what lies inside one or more signature envelopes.
type ExtractedDocument struct {
	// Path is where the document was written.
	Path string
	// Layers is how many envelopes were opened: an Italian document signed by
	// two people one after the other often arrives as name.pdf.p7m.p7m.
	Layers int
	Size   int
}

// ExtractedName is the default name of the document inside an envelope: the
// envelope's name without its .p7m/.p7s/.tsd suffixes, so
// contratto.pdf.p7m.tsd gives contratto.pdf beside it.
func ExtractedName(envelope string) string {
	name := envelope
	for {
		lower := strings.ToLower(name)
		switch {
		case strings.HasSuffix(lower, ".p7m"), strings.HasSuffix(lower, ".p7s"), strings.HasSuffix(lower, ".tsd"):
			name = name[:len(name)-4]
		default:
			if name == envelope || filepath.Base(name) == "" {
				return envelope + ".extracted"
			}
			return name
		}
	}
}
