package pdffield

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/digitorus/pdf"
)

// dictionaryWith writes a dictionary again, with entries changed or added.
// Its other entries are written as read: an indirect one as a reference.
func dictionaryWith(dictionary pdf.Value, changes map[string]string) string {
	var out strings.Builder
	out.WriteString("<<")
	keys := dictionary.Keys()
	for _, key := range keys {
		if _, changed := changes[key]; changed {
			continue
		}
		fmt.Fprintf(&out, " %s %s", name(key), serialize(dictionary, dictionary.Key(key), 0))
	}
	added := make([]string, 0, len(changes))
	for key := range changes {
		added = append(added, key)
	}
	slices.Sort(added)
	for _, key := range added {
		fmt.Fprintf(&out, " %s %s", name(key), changes[key])
	}
	out.WriteString(" >>")
	return out.String()
}

// serialize writes a value found in parent: a reference when it is another
// object (the PDF library resolves references, and gives a direct value its
// container's number), the value itself otherwise.
func serialize(parent, value pdf.Value, depth int) string {
	if depth > 32 {
		return "null"
	}
	if pointer := value.GetPtr(); pointer.GetID() != 0 && pointer != parent.GetPtr() {
		return fmt.Sprintf("%d %d R", pointer.GetID(), pointer.GetGen())
	}
	switch value.Kind() {
	case pdf.Bool:
		return strconv.FormatBool(value.Bool())
	case pdf.Integer:
		return strconv.FormatInt(value.Int64(), 10)
	case pdf.Real:
		return number(value.Float64())
	case pdf.String:
		return pdfString(value.RawString())
	case pdf.Name:
		return name(value.Name())
	case pdf.Array:
		parts := make([]string, value.Len())
		for index := range parts {
			parts[index] = serialize(value, value.Index(index), depth+1)
		}
		return "[" + strings.Join(parts, " ") + "]"
	case pdf.Dict:
		var out strings.Builder
		out.WriteString("<<")
		for _, key := range value.Keys() {
			fmt.Fprintf(&out, " %s %s", name(key), serialize(value, value.Key(key), depth+1))
		}
		out.WriteString(" >>")
		return out.String()
	}
	return "null"
}

// reference is an indirect value's reference.
func reference(value pdf.Value) string {
	pointer := value.GetPtr()
	return fmt.Sprintf("%d %d R", pointer.GetID(), pointer.GetGen())
}

// pdfText writes a text string a reader shows (ISO 32000-1, 7.9.2.2): as
// is when it is plain ASCII, otherwise in UTF-16BE behind its byte order
// mark; the bytes of UTF-8 would read as PDFDocEncoding, "Müller" as
// "MÃ¼ller".
func pdfText(text string) string {
	plain := true
	for _, character := range text {
		plain = plain && character >= 0x20 && character < 0x7F
	}
	if plain {
		return pdfString(text)
	}
	encoded := []byte{0xFE, 0xFF}
	for _, unit := range utf16.Encode([]rune(text)) {
		encoded = append(encoded, byte(unit>>8), byte(unit))
	}
	return fmt.Sprintf("<%X>", encoded)
}

// pdfString writes a string in hexadecimal, which needs no escaping.
func pdfString(text string) string {
	return fmt.Sprintf("<%X>", []byte(text))
}

// name writes a name, its delimiters and non-regular bytes as #xx
// (ISO 32000-1, 7.3.5).
func name(text string) string {
	var out strings.Builder
	out.WriteByte('/')
	for index := 0; index < len(text); index++ {
		character := text[index]
		if character < '!' || character > '~' || strings.IndexByte("#()<>[]{}/%", character) >= 0 {
			fmt.Fprintf(&out, "#%02X", character)
			continue
		}
		out.WriteByte(character)
	}
	return out.String()
}

// number writes a real number without an exponent, as PDF requires.
func number(value float64) string {
	text := strconv.FormatFloat(value, 'f', 4, 64)
	text = strings.TrimRight(strings.TrimRight(text, "0"), ".")
	if text == "" || text == "-" || text == "-0" {
		return "0"
	}
	return text
}
