package integration_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/helvetica"
)

// TestALongWordIsCutBetweenCharacters: a word wider than the line is broken,
// and never inside a UTF-8 character (the cut used to count bytes).
func TestALongWordIsCutBetweenCharacters(t *testing.T) {
	word := strings.Repeat("ÁÉÍÓÚÑÀÈÌÒÙ", 6)
	lines := helvetica.Wrap(word, 60, 10, false)
	if len(lines) < 2 {
		t.Fatalf("the word must be broken, got %d lines", len(lines))
	}
	if strings.Join(lines, "") != word {
		t.Error("breaking must not lose or add characters")
	}
	for _, line := range lines {
		if !utf8.ValidString(line) {
			t.Fatalf("line %q is not valid UTF-8: a character was cut", line)
		}
		if helvetica.Width(line, 10, false) > 60 {
			t.Errorf("line %q is wider than the box", line)
		}
	}
}

// TestWordsWrapWithinTheWidth.
func TestWordsWrapWithinTheWidth(t *testing.T) {
	lines := helvetica.Wrap("MARIA DEL CARMEN LOPEZ GARCIA MARTINEZ", 120, 10, true)
	for _, line := range lines {
		if helvetica.Width(line, 10, true) > 120 {
			t.Errorf("line %q overflows", line)
		}
	}
	if strings.Join(lines, " ") != "MARIA DEL CARMEN LOPEZ GARCIA MARTINEZ" {
		t.Errorf("lines %q", lines)
	}
}
