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

// TestTheEncodingNamesTheLettersWinAnsiLacks: WinAnsi letters stay as they
// are, each other Central or Eastern European letter takes a free code the
// encoding then names, once; a line break is a space; a character with no
// glyph, or one more than the free codes hold, is "?".
func TestTheEncodingNamesTheLettersWinAnsiLacks(t *testing.T) {
	plain := helvetica.NewEncoding()
	if encoded := string(plain.Encode("Pérez\nÑandú")); encoded != "P\xe9rez \xd1and\xfa" || plain.Dictionary() != "/WinAnsiEncoding" {
		t.Errorf("WinAnsi text: %q, %s", encoded, plain.Dictionary())
	}

	encoding := helvetica.NewEncoding()
	encoded := encoding.Encode("Zażółć gęślą jaźń Ω")
	again := encoding.Encode("łąka")
	if encoded[2] != 0x81 || encoded[3] != 0xf3 || encoded[4] != 0x8d || encoded[len(encoded)-1] != '?' || again[0] != 0x8d {
		t.Errorf("encoded % x and % x", encoded, again)
	}
	if dictionary := encoding.Dictionary(); !strings.HasPrefix(dictionary, "<< /Type /Encoding /BaseEncoding /WinAnsiEncoding /Differences [ 1 /") ||
		!strings.Contains(dictionary, " 129 /zdotaccent 141 /lslash") || strings.Count(dictionary, "/lslash") != 1 {
		t.Errorf("dictionary %s", dictionary)
	}

	// Thirty-six free codes (Windows-1252's five holes and the 31 control
	// codes): the thirty-seventh new letter has no room.
	crowded := helvetica.NewEncoding()
	letters := []rune("ĄąĆćĘęŁłŃńŚśŹźŻżČčĎďĚěŇňŘřŤťŮůĹĺĽľŔŕŐőŰűĂă")
	out := crowded.Encode(string(letters))
	if out[35] == '?' || out[36] != '?' || out[len(out)-1] != '?' {
		t.Errorf("the free codes overflow at % x", out[34:])
	}
}
