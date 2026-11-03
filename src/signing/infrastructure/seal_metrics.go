package infrastructure

// Helvetica advance widths in 1/1000 em, from the Adobe AFM metrics.
//
// A seal has to wrap text inside a fixed width, and guessing character widths
// with a fixed average produces either clipped lines or a ragged block. These
// tables make the wrap exact for the base-14 fonts every PDF reader has, so the
// layout is stable across viewers and across machines.
//
// Unknown runes fall back to a digit width, which errs on the wide side: the
// wrap breaks earlier rather than letting text overflow the box.

// helveticaRegular maps ASCII to advance widths for Helvetica.
var helveticaRegular = map[rune]int{
	' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667,
	'\'': 191, '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333,
	'.': 278, '/': 278,
	'0': 556, '1': 556, '2': 556, '3': 556, '4': 556,
	'5': 556, '6': 556, '7': 556, '8': 556, '9': 556,
	':': 278, ';': 278, '<': 584, '=': 584, '>': 584, '?': 556, '@': 1015,
	'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778,
	'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722,
	'O': 778, 'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722,
	'V': 667, 'W': 944, 'X': 667, 'Y': 667, 'Z': 611,
	'[': 278, '\\': 278, ']': 278, '^': 469, '_': 556, '`': 333,
	'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556,
	'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556,
	'o': 556, 'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556,
	'v': 500, 'w': 722, 'x': 500, 'y': 500, 'z': 500,
	'{': 334, '|': 260, '}': 334, '~': 584,
}

// helveticaBold maps the characters the name line needs.
var helveticaBold = map[rune]int{
	' ': 278, '-': 333, '.': 278, '\'': 238, ',': 278,
	'0': 556, '1': 556, '2': 556, '3': 556, '4': 556,
	'5': 556, '6': 556, '7': 556, '8': 556, '9': 556,
	'A': 722, 'B': 722, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778,
	'H': 722, 'I': 278, 'J': 556, 'K': 722, 'L': 611, 'M': 833, 'N': 722,
	'O': 778, 'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722,
	'V': 667, 'W': 944, 'X': 667, 'Y': 667, 'Z': 611,
	'a': 556, 'b': 611, 'c': 556, 'd': 611, 'e': 556, 'f': 333, 'g': 611,
	'h': 611, 'i': 278, 'j': 278, 'k': 556, 'l': 278, 'm': 889, 'n': 611,
	'o': 611, 'p': 611, 'q': 611, 'r': 389, 's': 556, 't': 333, 'u': 611,
	'v': 556, 'w': 778, 'x': 556, 'y': 556, 'z': 500,
}

// fallbackWidth is used for runes outside the tables (accents, CJK, symbols).
const fallbackWidth = 556

// textWidth returns the rendered width of a string in points.
func textWidth(text string, size float64, bold bool) float64 {
	table := helveticaRegular
	if bold {
		table = helveticaBold
	}

	total := 0
	for _, character := range text {
		width, ok := table[character]
		if !ok {
			width = fallbackWidth
		}
		total += width
	}
	return float64(total) * size / 1000.0
}

// wrapToWidth breaks text so every line fits within maxWidth points.
//
// It never splits a word unless the word alone is wider than the line, in which
// case it splits on rune boundaries: a fiscal identifier with no spaces must
// still be printable, and dropping it would be worse than breaking it.
func wrapToWidth(text string, maxWidth, size float64, bold bool) []string {
	var lines []string
	current := ""

	for _, word := range splitWords(text) {
		candidate := word
		if current != "" {
			candidate = current + " " + word
		}
		if textWidth(candidate, size, bold) <= maxWidth {
			current = candidate
			continue
		}
		if current != "" {
			lines = append(lines, current)
			current = ""
		}
		// The word alone may still be too long.
		for textWidth(word, size, bold) > maxWidth && len(word) > 1 {
			cut := len(word)
			for cut > 1 && textWidth(word[:cut], size, bold) > maxWidth {
				cut--
			}
			lines = append(lines, word[:cut])
			word = word[cut:]
		}
		current = word
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

// splitWords splits on whitespace, collapsing runs.
func splitWords(text string) []string {
	var words []string
	start := -1
	for index, character := range text {
		if character == ' ' || character == '\t' || character == '\n' || character == '\r' {
			if start >= 0 {
				words = append(words, text[start:index])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = index
		}
	}
	if start >= 0 {
		words = append(words, text[start:])
	}
	return words
}
