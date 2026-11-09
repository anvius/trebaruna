package infrastructure

import (
	"bytes"
	"io"
	"regexp"
	"strconv"

	"github.com/digitorus/pdf"
)

// pdfaPattern finds the PDF/A part an XMP packet claims, as an attribute or
// an element, quoted either way (ISO 19005-1, 6.7.11).
var pdfaPattern = regexp.MustCompile(`pdfaid:part(?:=["']|>)\s*(\d)`)

// pdfaPart is the PDF/A part a document's metadata claims, 0 for none.
func pdfaPart(content []byte) int {
	reader, err := pdf.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return 0
	}
	metadata := reader.Trailer().Key("Root").Key("Metadata")
	if metadata.Kind() != pdf.Stream {
		return 0
	}
	packet, err := io.ReadAll(io.LimitReader(metadata.Reader(), 1<<20))
	if err != nil {
		return 0
	}
	match := pdfaPattern.FindSubmatch(packet)
	if match == nil {
		return 0
	}
	part, _ := strconv.Atoi(string(match[1]))
	return part
}

// faceFor sets a PDF/A document's seal in embedded fonts, as the standard
// asks of every font shown; any other in Helvetica, which readers have.
func faceFor(content []byte) sealFace {
	if pdfaPart(content) > 0 {
		return embeddedFace{}
	}
	return standardFace{}
}
