package infrastructure

import "fmt"

// Minimal DER walking, used to re-read values the CMS library keeps private.
//
// The parsing is deliberately shallow: it splits one level of a SEQUENCE and
// returns the raw encodings of its elements. Deep parsing is not needed and
// would duplicate work the library already does correctly.

// splitDerSequence returns the raw encoding of each element inside a SEQUENCE.
func splitDerSequence(data []byte) ([][]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("der: need at least 2 bytes, got %d", len(data))
	}

	body, err := sequenceBody(data)
	if err != nil {
		return nil, err
	}

	var elements [][]byte
	remaining := body
	for len(remaining) > 0 {
		total, err := elementSize(remaining)
		if err != nil {
			return nil, err
		}
		elements = append(elements, remaining[:total])
		remaining = remaining[total:]
	}
	return elements, nil
}

// sequenceBody strips the tag and length of a SEQUENCE or SET.
func sequenceBody(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("der: truncated element")
	}
	if data[0] != 0x30 && data[0] != 0x31 {
		return nil, fmt.Errorf("der: expected SEQUENCE or SET, got 0x%02x", data[0])
	}

	length, headerSize, ok := readLength(data, 1)
	if !ok {
		return nil, fmt.Errorf("der: bad length")
	}
	start := 1 + headerSize
	if start+length > len(data) {
		return nil, fmt.Errorf("der: length %d exceeds buffer %d", length, len(data)-start)
	}
	return data[start : start+length], nil
}

// elementSize returns the total encoded size of the first element.
func elementSize(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("der: truncated element")
	}
	length, headerSize, ok := readLength(data, 1)
	if !ok {
		return 0, fmt.Errorf("der: bad length")
	}
	total := 1 + headerSize + length
	if total > len(data) {
		return 0, fmt.Errorf("der: declared length exceeds buffer")
	}
	return total, nil
}

// unwrapExplicit strips a context-specific explicit tag such as [0].
func unwrapExplicit(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0]&0xe0 != 0xa0 {
		return nil, fmt.Errorf("der: expected an explicit context tag")
	}
	length, headerSize, ok := readLength(data, 1)
	if !ok {
		return nil, fmt.Errorf("der: bad length")
	}
	start := 1 + headerSize
	if start+length > len(data) {
		return nil, fmt.Errorf("der: length exceeds buffer")
	}
	return data[start : start+length], nil
}
