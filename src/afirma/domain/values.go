package domain

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"strings"
	"unicode/utf8"
)

// DecodeBase64 reads Base64 the tolerant way AutoFirma does (A.3): either
// alphabet, spaces taken for "+" (a "+" a form-decoder turned into a space),
// line breaks skipped, padding optional.
func DecodeBase64(text string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '-':
			return '+'
		case '_':
			return '/'
		case ' ':
			return '+'
		case '\r', '\n', '\t':
			return -1
		}
		return r
	}, text)
	cleaned = strings.TrimRight(cleaned, "=")
	return base64.RawStdEncoding.DecodeString(cleaned)
}

// EncodeBase64URL is URL-safe Base64 with padding, what AutoFirma answers
// with and the only alphabet that survives the storage servlet (B.1).
func EncodeBase64URL(data []byte) string { return base64.URLEncoding.EncodeToString(data) }

// looksLikeBase64 is AutoFirma's test for dat (A.3): only Base64 characters
// of either alphabet, "=" only in the last two places, and a length (without
// line breaks) that is a multiple of four. Unpadded Base64 is text to it.
func looksLikeBase64(text string) bool {
	count := 0
	for index, r := range text {
		switch {
		case r == '\r' || r == '\n':
			continue
		case r == '=':
			if index < len(text)-2 {
				return false
			}
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '+', r == '/', r == '-', r == '_', r == '~', r == '\t', r == ' ':
		default:
			return false
		}
		count++
	}
	return count > 0 && count%4 == 0
}

// Payload is what a request carries to sign or save.
type Payload struct {
	// Bytes is the data itself.
	Bytes []byte
	// URL is set when the page points at the data instead of sending it;
	// AutoFirma downloads it silently, trebaruna only after the person sees it.
	URL string
}

// Absent reports a request without data: the person picks a file.
func (p Payload) Absent() bool { return len(p.Bytes) == 0 && p.URL == "" }

// ResolvePayload reads dat (A.3): a file URL is refused, gzip unpacked, a web
// address kept to show, Base64 decoded, anything else taken as text.
func ResolvePayload(dat string, gzipped bool) (Payload, error) {
	switch {
	case dat == "":
		return Payload{}, nil
	case strings.HasPrefix(dat, "file:/"):
		return Payload{}, Failure{Code: Params, Cause: "dat may not name a local file"}
	case gzipped && looksLikeBase64(dat):
		packed, err := DecodeBase64(dat)
		if err != nil {
			return Payload{}, Failure{Code: Params, Cause: "undecodable gzip data"}
		}
		reader, err := gzip.NewReader(bytes.NewReader(packed))
		if err != nil {
			return Payload{}, Failure{Code: Params, Cause: "data are not gzip"}
		}
		unpacked, err := io.ReadAll(reader)
		if err != nil {
			return Payload{}, Failure{Code: Params, Cause: "data are not gzip"}
		}
		return Payload{Bytes: unpacked}, nil
	case strings.HasPrefix(dat, "http://") || strings.HasPrefix(dat, "https://"):
		return Payload{URL: dat}, nil
	case looksLikeBase64(dat):
		decoded, err := DecodeBase64(dat)
		if err == nil {
			return Payload{Bytes: decoded}, nil
		}
	}
	return Payload{Bytes: []byte(dat)}, nil
}

// ParseProperties reads Java .properties text (A.7): "key=value",
// "key:value" or "key value", "#"/"!" comments, backslash escapes, "\uXXXX"
// and continued lines.
func ParseProperties(text string) map[string]string {
	properties := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for index := 0; index < len(lines); index++ {
		line := strings.TrimLeft(lines[index], " \t\f")
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		// An odd number of trailing backslashes continues the line.
		for endsContinued(line) && index+1 < len(lines) {
			index++
			line = line[:len(line)-1] + strings.TrimLeft(lines[index], " \t\f")
		}
		key, value := splitProperty(line)
		properties[unescapeProperty(key)] = unescapeProperty(value)
	}
	return properties
}

// endsContinued reports an odd run of trailing backslashes.
func endsContinued(line string) bool {
	count := 0
	for index := len(line) - 1; index >= 0 && line[index] == '\\'; index-- {
		count++
	}
	return count%2 == 1
}

// splitProperty cuts at the first unescaped "=", ":" or whitespace.
func splitProperty(line string) (string, string) {
	for index := 0; index < len(line); index++ {
		switch line[index] {
		case '\\':
			index++
		case '=', ':', ' ', '\t', '\f':
			key := line[:index]
			rest := strings.TrimLeft(line[index:], " \t\f")
			if rest != "" && (rest[0] == '=' || rest[0] == ':') {
				rest = strings.TrimLeft(rest[1:], " \t\f")
			}
			return key, rest
		}
	}
	return line, ""
}

// unescapeProperty resolves backslash escapes.
func unescapeProperty(text string) string {
	if !strings.Contains(text, "\\") {
		return text
	}
	var builder strings.Builder
	for index := 0; index < len(text); index++ {
		if text[index] != '\\' || index+1 >= len(text) {
			builder.WriteByte(text[index])
			continue
		}
		index++
		switch text[index] {
		case 't':
			builder.WriteByte('\t')
		case 'n':
			builder.WriteByte('\n')
		case 'r':
			builder.WriteByte('\r')
		case 'f':
			builder.WriteByte('\f')
		case 'u':
			if index+4 < len(text) {
				var code rune
				valid := true
				for _, digit := range text[index+1 : index+5] {
					code <<= 4
					switch {
					case digit >= '0' && digit <= '9':
						code |= digit - '0'
					case digit >= 'a' && digit <= 'f':
						code |= digit - 'a' + 10
					case digit >= 'A' && digit <= 'F':
						code |= digit - 'A' + 10
					default:
						valid = false
					}
				}
				if valid {
					builder.WriteRune(code)
					index += 4
					continue
				}
			}
			builder.WriteByte('u')
		default:
			builder.WriteByte(text[index])
		}
	}
	if !utf8.ValidString(builder.String()) {
		return text
	}
	return builder.String()
}

// DecodeProperties reads the properties parameter: Base64 (either alphabet)
// of properties text; undecodable is empty, as AutoFirma logs and goes on.
func DecodeProperties(encoded string) map[string]string {
	if encoded == "" {
		return map[string]string{}
	}
	decoded, err := DecodeBase64(encoded)
	if err != nil {
		return map[string]string{}
	}
	return ParseProperties(string(decoded))
}
