package cms

import (
	"encoding/asn1"
	"fmt"
)

// splitSequence returns the DER of each element of a SEQUENCE.
func splitSequence(derBytes []byte) ([][]byte, error) {
	body, err := sequenceBody(derBytes)
	if err != nil {
		return nil, err
	}
	return splitElements(body)
}

// sequenceBody strips the outer tag and length.
func sequenceBody(derBytes []byte) ([]byte, error) {
	tag, _, contents, err := parseTLV(derBytes)
	if err != nil {
		return nil, err
	}
	if tag != 0x30 && tag != 0x31 {
		return nil, fmt.Errorf("cms: expected SEQUENCE or SET, got tag 0x%02x", tag)
	}
	return contents, nil
}

// splitElements walks a concatenation of DER elements.
func splitElements(body []byte) ([][]byte, error) {
	var elements [][]byte
	remaining := body
	for len(remaining) > 0 {
		tag, lengthSize, contents, err := parseTLV(remaining)
		if err != nil {
			return nil, err
		}
		_ = tag
		headerSize := 1 + lengthSize
		total := headerSize + len(contents)
		if total > len(remaining) {
			return nil, fmt.Errorf("cms: truncated element: want %d bytes, have %d", total, len(remaining))
		}
		element := make([]byte, total)
		copy(element, remaining[:total])
		elements = append(elements, element)
		remaining = remaining[total:]
	}
	return elements, nil
}

// parseTLV decodes one tag-length-value and returns its parts.
func parseTLV(derBytes []byte) (tag byte, lengthSize int, contents []byte, err error) {
	if len(derBytes) < 2 {
		return 0, 0, nil, fmt.Errorf("cms: need at least 2 bytes for a TLV, got %d", len(derBytes))
	}

	tag = derBytes[0]
	first := derBytes[1]

	if first < 0x80 {
		if 2+int(first) > len(derBytes) {
			return 0, 0, nil, fmt.Errorf("cms: declared length %d exceeds buffer %d", first, len(derBytes)-2)
		}
		return tag, 1, derBytes[2 : 2+int(first)], nil
	}

	lengthBytes := int(first & 0x7f)
	// A TimeStampToken easily exceeds 4 GiB of declared length? No — but the
	// TSA response wraps the token in BER with long-form lengths, and 6-byte
	// lengths (0x86) appear in practice. Accept up to 8 to stay safe.
	if lengthBytes == 0 || lengthBytes > 8 {
		return 0, 0, nil, fmt.Errorf("cms: unsupported length encoding (0x%02x)", first)
	}
	if 2+lengthBytes > len(derBytes) {
		return 0, 0, nil, fmt.Errorf("cms: truncated length field")
	}

	length := 0
	for index := 0; index < lengthBytes; index++ {
		length = length<<8 | int(derBytes[2+index])
		if length < 0 {
			return 0, 0, nil, fmt.Errorf("cms: length overflow")
		}
	}

	start := 2 + lengthBytes
	if start+length > len(derBytes) {
		return 0, 0, nil, fmt.Errorf("cms: declared length %d exceeds buffer %d", length, len(derBytes)-start)
	}
	return tag, 1 + lengthBytes, derBytes[start : start+length], nil
}

// compile-time guard: asn1 must stay imported for the error wrapping above.
var _ = asn1.Unmarshal
