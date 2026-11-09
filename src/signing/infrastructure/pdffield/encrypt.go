package pdffield

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/digitorus/pdf"
)

// An encrypted document's update must encrypt every string and stream of
// the objects it writes, each with that object's key (ISO 32000-1, 7.6.1),
// except the signature dictionary's /Contents, filled in after signing
// (7.6.2), and the cross-reference stream (7.5.8). The document's own
// reader encrypts with its key and crypt filter.

// encryptObject returns an object's dictionary with its strings encrypted
// (written as hexadecimal strings) and its stream data encrypted, /Length
// following. skipContents leaves the /Contents string as it is.
func encryptObject(reader *pdf.Reader, id uint32, generation int, dictionary string, data []byte, skipContents bool) (string, []byte, error) {
	pointer := pdf.NewPtr(id, uint16(generation))
	encrypted, err := encryptStrings(reader, pointer, dictionary, skipContents)
	if err != nil {
		return "", nil, err
	}
	if data == nil {
		return encrypted, nil, nil
	}
	sealed, err := reader.Encrypt(pointer, data)
	if err != nil {
		return "", nil, err
	}
	return lengthPattern.ReplaceAllString(encrypted, "/Length "+strconv.Itoa(len(sealed))), sealed, nil
}

var lengthPattern = regexp.MustCompile(`/Length \d+`)

// encryptStrings rewrites each literal or hexadecimal string of a PDF
// object's text as the hexadecimal string of its encryption.
func encryptStrings(reader *pdf.Reader, pointer pdf.Ptr, text string, skipContents bool) (string, error) {
	var out strings.Builder
	skipNext := false
	for index := 0; index < len(text); {
		switch {
		case strings.HasPrefix(text[index:], "<<"):
			// A dictionary opens: both brackets at once, or the second would
			// read as a hexadecimal string.
			out.WriteString("<<")
			index += 2
		case strings.HasPrefix(text[index:], "/Contents") && skipContents:
			out.WriteString("/Contents")
			index += len("/Contents")
			skipNext = true
		case text[index] == '(' || text[index] == '<':
			value, end, err := readString(text, index)
			if err != nil {
				return "", err
			}
			if skipNext {
				out.WriteString(text[index:end])
			} else {
				sealed, err := reader.Encrypt(pointer, value)
				if err != nil {
					return "", err
				}
				out.WriteString("<" + strings.ToUpper(hex.EncodeToString(sealed)) + ">")
			}
			skipNext = false
			index = end
		case text[index] == '/':
			// Another name: a /Contents just read held no string.
			skipNext = false
			out.WriteByte('/')
			index++
		default:
			out.WriteByte(text[index])
			index++
		}
	}
	return out.String(), nil
}

// readString reads the string starting at index, literal or hexadecimal,
// and returns its bytes and the index after it.
func readString(text string, index int) ([]byte, int, error) {
	if text[index] == '<' {
		end := strings.IndexByte(text[index:], '>')
		if end < 0 {
			return nil, 0, fmt.Errorf("%w: an unterminated hexadecimal string", ErrUnsupported)
		}
		digits := strings.Join(strings.Fields(text[index+1:index+end]), "")
		if len(digits)%2 == 1 {
			digits += "0"
		}
		value, err := hex.DecodeString(digits)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: a malformed hexadecimal string", ErrUnsupported)
		}
		return value, index + end + 1, nil
	}
	var value bytes.Buffer
	depth := 0
	for position := index; position < len(text); position++ {
		character := text[position]
		switch {
		case character == '\\' && position+1 < len(text):
			position++
			escaped := text[position]
			switch escaped {
			case 'n':
				value.WriteByte('\n')
			case 'r':
				value.WriteByte('\r')
			case 't':
				value.WriteByte('\t')
			case 'b':
				value.WriteByte('\b')
			case 'f':
				value.WriteByte('\f')
			case '\r', '\n':
				// A line continuation.
			default:
				if escaped >= '0' && escaped <= '7' {
					end := position + 1
					for end < len(text) && end < position+3 && text[end] >= '0' && text[end] <= '7' {
						end++
					}
					code, _ := strconv.ParseUint(text[position:end], 8, 8)
					value.WriteByte(byte(code))
					position = end - 1
				} else {
					value.WriteByte(escaped)
				}
			}
		case character == '(':
			if depth > 0 {
				value.WriteByte(character)
			}
			depth++
		case character == ')':
			depth--
			if depth == 0 {
				return value.Bytes(), position + 1, nil
			}
			value.WriteByte(character)
		default:
			value.WriteByte(character)
		}
	}
	return nil, 0, fmt.Errorf("%w: an unterminated string", ErrUnsupported)
}
