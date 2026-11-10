package helvetica

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// Encoding writes text for the standard Helvetica faces: WinAnsi, which
// covers Western European letters, and, for the letters it lacks, the
// glyphs Helvetica has for the languages of Central and Eastern Europe
// (Polish, Czech, Slovak, Hungarian, Romanian, Croatian, Slovene, the
// Baltic languages, Turkish) put in the codes WinAnsi leaves without a
// glyph, which the font's encoding then names in a /Differences array. A
// character with no glyph, or one more than the free codes hold, prints
// as "?". One Encoding serves every text of one font dictionary.
type Encoding struct {
	codes map[rune]byte
}

// NewEncoding is an encoding that has assigned no extra glyph yet.
func NewEncoding() *Encoding { return &Encoding{codes: map[rune]byte{}} }

// freeCodes are the codes WinAnsiEncoding leaves without a glyph: the
// five holes of Windows-1252, then the control codes.
var freeCodes = func() []byte {
	codes := []byte{0x81, 0x8d, 0x8f, 0x90, 0x9d}
	for code := byte(0x01); code < 0x20; code++ {
		codes = append(codes, code)
	}
	return codes
}()

// extendedGlyphs are the Adobe glyph names of the letters WinAnsi lacks
// that the standard Helvetica faces carry.
var extendedGlyphs = map[rune]string{
	'Ą': "Aogonek", 'ą': "aogonek", 'Ć': "Cacute", 'ć': "cacute", 'Ę': "Eogonek", 'ę': "eogonek",
	'Ł': "Lslash", 'ł': "lslash", 'Ń': "Nacute", 'ń': "nacute", 'Ś': "Sacute", 'ś': "sacute",
	'Ź': "Zacute", 'ź': "zacute", 'Ż': "Zdotaccent", 'ż': "zdotaccent",
	'Č': "Ccaron", 'č': "ccaron", 'Ď': "Dcaron", 'ď': "dcaron", 'Ě': "Ecaron", 'ě': "ecaron",
	'Ň': "Ncaron", 'ň': "ncaron", 'Ř': "Rcaron", 'ř': "rcaron", 'Ť': "Tcaron", 'ť': "tcaron",
	'Ů': "Uring", 'ů': "uring", 'Ĺ': "Lacute", 'ĺ': "lacute", 'Ľ': "Lcaron", 'ľ': "lcaron",
	'Ŕ': "Racute", 'ŕ': "racute",
	'Ő': "Ohungarumlaut", 'ő': "ohungarumlaut", 'Ű': "Uhungarumlaut", 'ű': "uhungarumlaut",
	'Ă': "Abreve", 'ă': "abreve", 'Ș': "Scommaaccent", 'ș': "scommaaccent", 'Ț': "Tcommaaccent", 'ț': "tcommaaccent",
	'Ş': "Scedilla", 'ş': "scedilla", 'Ţ': "Tcedilla", 'ţ': "tcedilla",
	'Đ': "Dcroat", 'đ': "dcroat",
	'Ā': "Amacron", 'ā': "amacron", 'Ē': "Emacron", 'ē': "emacron", 'Ī': "Imacron", 'ī': "imacron",
	'Ū': "Umacron", 'ū': "umacron", 'Ō': "Omacron", 'ō': "omacron", 'Ė': "Edotaccent", 'ė': "edotaccent",
	'Į': "Iogonek", 'į': "iogonek", 'Ų': "Uogonek", 'ų': "uogonek",
	'Ģ': "Gcommaaccent", 'ģ': "gcommaaccent", 'Ķ': "Kcommaaccent", 'ķ': "kcommaaccent",
	'Ļ': "Lcommaaccent", 'ļ': "lcommaaccent", 'Ņ': "Ncommaaccent", 'ņ': "ncommaaccent",
	'Ŗ': "Rcommaaccent", 'ŗ': "rcommaaccent",
	'Ğ': "Gbreve", 'ğ': "gbreve", 'İ': "Idotaccent", 'ı': "dotlessi",
}

// Encode is the text's bytes in this encoding: line breaks and other
// control characters as spaces, a letter WinAnsi lacks in a free code.
func (e *Encoding) Encode(text string) []byte {
	var out []byte
	for _, character := range text {
		if character < 0x20 {
			out = append(out, ' ')
			continue
		}
		if code, ok := charmap.Windows1252.EncodeRune(character); ok {
			out = append(out, code)
			continue
		}
		code, assigned := e.codes[character]
		if _, known := extendedGlyphs[character]; known && !assigned && len(e.codes) < len(freeCodes) {
			code, assigned = freeCodes[len(e.codes)], true
			e.codes[character] = code
		}
		if !assigned {
			code = '?'
		}
		out = append(out, code)
	}
	return out
}

// Dictionary is the font's /Encoding: /WinAnsiEncoding, or a dictionary
// over it naming the extra glyphs the texts used.
func (e *Encoding) Dictionary() string {
	if len(e.codes) == 0 {
		return "/WinAnsiEncoding"
	}
	codes := make([]int, 0, len(e.codes))
	names := map[int]string{}
	for character, code := range e.codes {
		codes = append(codes, int(code))
		names[int(code)] = extendedGlyphs[character]
	}
	sort.Ints(codes)
	var differences strings.Builder
	for _, code := range codes {
		fmt.Fprintf(&differences, " %d /%s", code, names[code])
	}
	return "<< /Type /Encoding /BaseEncoding /WinAnsiEncoding /Differences [" + differences.String() + " ] >>"
}
