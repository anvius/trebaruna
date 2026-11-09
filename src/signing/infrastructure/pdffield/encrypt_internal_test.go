package pdffield

import "testing"

// TestStringsAreReadAsPDFWritesThem: literal strings with escapes, octal
// codes and balanced parentheses, hexadecimal strings with spaces and an
// odd digit.
func TestStringsAreReadAsPDFWritesThem(t *testing.T) {
	for text, want := range map[string]string{
		`(Mario \(Rossi\))`: "Mario (Rossi)",
		`(a (nested) one)`:  "a (nested) one",
		`(line\nbreak\t\\)`: "line\nbreak\t\\",
		`(\101\102C)`:       "ABC",
		"(con\\\ntinued)":   "continued",
		`<4D 61 72 69 6F>`:  "Mario",
		`<4D6172696F7>`:     "Mario\x70",
	} {
		value, end, err := readString(text, 0)
		if err != nil || string(value) != want || end != len(text) {
			t.Errorf("%q: %q, end %d, %v", text, value, end, err)
		}
	}
	for _, broken := range []string{`(open`, `<4D61`, `<zz>`} {
		if _, _, err := readString(broken, 0); err == nil {
			t.Errorf("%q was read", broken)
		}
	}
}
