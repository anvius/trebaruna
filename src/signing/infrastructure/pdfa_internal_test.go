package infrastructure

import "testing"

// TestThePDFAPartIsReadHoweverTheXMPWritesIt: an attribute quoted either
// way, or an element.
func TestThePDFAPartIsReadHoweverTheXMPWritesIt(t *testing.T) {
	for packet, want := range map[string]string{
		`<rdf:Description pdfaid:part='1' pdfaid:conformance='B'/>`: "1",
		`<rdf:Description pdfaid:part="2" pdfaid:conformance="B"/>`: "2",
		`<pdfaid:part>3</pdfaid:part>`:                              "3",
		`<pdfaid:part> 2 </pdfaid:part>`:                            "2",
	} {
		match := pdfaPattern.FindStringSubmatch(packet)
		if match == nil || match[1] != want {
			t.Errorf("%s: %v", packet, match)
		}
	}
	if pdfaPattern.MatchString(`<pdfuaid:part>1</pdfuaid:part>`) {
		t.Error("PDF/UA is not PDF/A")
	}
}
