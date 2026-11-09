// Package ber rewrites BER encodings as DER. CMS and PKCS#12 allow BER, and
// other tools write it (NSS for PKCS#12, many signers for .p7m), while Go's
// encoding/asn1 and the hand-written CMS code read DER only.
package ber

import (
	"errors"
	"fmt"
)

// ToDER rewrites one BER element as DER: every length becomes definite
// and minimal, and constructed strings are flattened into primitive ones.
//
// PKCS#12 allows BER and NSS (Firefox, Thunderbird) uses it, while Go's
// encoding/asn1 reads DER only. The contents of OCTET STRINGs are copied
// unchanged, which matters: the integrity MAC of a PKCS#12 file is computed
// over the bytes inside one of them.
func ToDER(data []byte) ([]byte, error) {
	element, rest, err := convert(data, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("ber: %d bytes after the encoding", len(rest))
	}
	return element, nil
}

// maxDepth bounds recursion on hostile input.
const maxDepth = 64

var errTruncated = errors.New("ber: truncated encoding")

// convert reads one element and returns it as DER plus the bytes after it.
func convert(data []byte, depth int) (element, rest []byte, err error) {
	if depth > maxDepth {
		return nil, nil, errors.New("ber: encoding nested too deeply")
	}
	tag, length, header, err := readHeader(data)
	if err != nil {
		return nil, nil, err
	}
	constructed := tag[0]&0x20 != 0

	if !constructed {
		if length < 0 {
			return nil, nil, errors.New("ber: indefinite length on a primitive element")
		}
		end := header + length
		return encode(tag, data[header:end]), data[end:], nil
	}

	var children [][]byte
	if length >= 0 {
		body := data[header : header+length]
		rest = data[header+length:]
		for len(body) > 0 {
			var child []byte
			if child, body, err = convert(body, depth+1); err != nil {
				return nil, nil, err
			}
			children = append(children, child)
		}
	} else {
		cursor := data[header:]
		for {
			if len(cursor) < 2 {
				return nil, nil, errTruncated
			}
			if cursor[0] == 0 && cursor[1] == 0 {
				rest = cursor[2:]
				break
			}
			var child []byte
			if child, cursor, err = convert(cursor, depth+1); err != nil {
				return nil, nil, err
			}
			children = append(children, child)
		}
	}

	if isUniversalString(tag) {
		flat, err := flatten(children, tag[0]&0x1f == 3)
		if err != nil {
			return nil, nil, err
		}
		return encode([]byte{tag[0] &^ 0x20}, flat), rest, nil
	}
	var body []byte
	for _, child := range children {
		body = append(body, child...)
	}
	return encode(tag, body), rest, nil
}

// readHeader parses a tag and a length. A length of -1 means indefinite.
func readHeader(data []byte) (tag []byte, length, header int, err error) {
	if len(data) < 2 {
		return nil, 0, 0, errTruncated
	}
	position := 1
	if data[0]&0x1f == 0x1f {
		// High tag number: base-128 digits, the last one without the top bit.
		for {
			if position >= len(data) {
				return nil, 0, 0, errTruncated
			}
			position++
			if data[position-1]&0x80 == 0 {
				break
			}
		}
	}
	tag = data[:position]
	if position >= len(data) {
		return nil, 0, 0, errTruncated
	}

	first := data[position]
	position++
	switch {
	case first == 0x80:
		return tag, -1, position, nil
	case first < 0x80:
		length = int(first)
	default:
		count := int(first & 0x7f)
		if count > 4 || position+count > len(data) {
			return nil, 0, 0, errors.New("ber: unsupported length encoding")
		}
		for _, digit := range data[position : position+count] {
			length = length<<8 | int(digit)
		}
		position += count
	}
	if length < 0 || position+length > len(data) {
		return nil, 0, 0, errTruncated
	}
	return tag, length, position, nil
}

// isUniversalString reports the universal string types BER may split into
// constructed pieces: BIT STRING, OCTET STRING and the character strings.
func isUniversalString(tag []byte) bool {
	if len(tag) != 1 || tag[0]&0xc0 != 0 {
		return false
	}
	switch tag[0] & 0x1f {
	case 3, 4, 12, 18, 19, 20, 22, 26, 28, 30:
		return true
	}
	return false
}

// flatten joins the contents of the DER pieces of a constructed string. A BIT
// STRING piece starts with its count of unused bits; only the last one's
// survives, in front of the joined bits.
func flatten(pieces [][]byte, bits bool) ([]byte, error) {
	var joined []byte
	unused := byte(0)
	for _, piece := range pieces {
		_, length, header, err := readHeader(piece)
		if err != nil {
			return nil, err
		}
		contents := piece[header : header+length]
		if bits {
			if len(contents) == 0 {
				return nil, errTruncated
			}
			unused, contents = contents[0], contents[1:]
		}
		joined = append(joined, contents...)
	}
	if bits {
		joined = append([]byte{unused}, joined...)
	}
	return joined, nil
}

// encode writes a tag, a minimal definite length and the contents.
func encode(tag, contents []byte) []byte {
	out := append([]byte{}, tag...)
	length := len(contents)
	switch {
	case length < 0x80:
		out = append(out, byte(length))
	default:
		var digits []byte
		for value := length; value > 0; value >>= 8 {
			digits = append([]byte{byte(value)}, digits...)
		}
		out = append(out, 0x80|byte(len(digits)))
		out = append(out, digits...)
	}
	return append(out, contents...)
}
