package parser_test

// A territory may publish several pointers in the EU list of the lists. Spain
// publishes TSL.pdf and TSL.xml, and the first match used to win: the code picked
// the PDF, then rejected the whole territory as unparseable, which made every
// Spanish qualified signature read as untrusted.
//
// The rule these tests pin: prefer the pointer this tool can both read and
// authenticate, and keep a non-XML one only so the reason stays accurate.

import (
	"testing"

	"codeberg.org/simplicer/firma-it/src/trust/domain"
)

// TestFindPrefersTheXMLPointer is the regression guard.
func TestFindPrefersTheXMLPointer(t *testing.T) {
	list := domain.LOTL{Entries: []domain.LOTLEntry{
		{Territory: "ES", Location: "https://tsl.digital.gob.es/TSL.pdf"},
		{Territory: "ES", Location: "https://tsl.digital.gob.es/TSL.xml",
			MimeType: "application/vnd.etsi.tsl+xml"},
	}}

	entry, found := list.Find("ES")
	if !found {
		t.Fatal("ES was not found")
	}
	if !entry.XML() {
		t.Errorf("Find returned the PDF pointer %q; the XML one is the one that can be parsed", entry.Location)
	}
}

// TestFindKeepsAnXMLPointerWhenItComesFirst: order must not matter.
func TestFindKeepsAnXMLPointerWhenItComesFirst(t *testing.T) {
	list := domain.LOTL{Entries: []domain.LOTLEntry{
		{Territory: "IT", Location: "https://example.org/tsl.xml", MimeType: "application/vnd.etsi.tsl+xml"},
		{Territory: "IT", Location: "https://example.org/tsl.pdf"},
	}}

	entry, found := list.Find("IT")
	if !found || !entry.XML() {
		t.Fatalf("entry = %+v, want the XML pointer", entry)
	}
}

// TestFindFallsBackToANonXMLPointer: a territory that only publishes a PDF must
// still be found, so the error can say why it cannot be used.
func TestFindFallsBackToANonXMLPointer(t *testing.T) {
	list := domain.LOTL{Entries: []domain.LOTLEntry{
		{Territory: "XX", Location: "https://example.org/tsl.pdf"},
	}}

	entry, found := list.Find("XX")
	if !found {
		t.Fatal("a PDF-only territory must still be found")
	}
	if entry.XML() {
		t.Error("a .pdf pointer must not report itself as XML")
	}
}

// TestFindIsCaseInsensitive keeps the CLI forgiving.
func TestFindIsCaseInsensitive(t *testing.T) {
	list := domain.LOTL{Entries: []domain.LOTLEntry{
		{Territory: "ES", Location: "https://example.org/tsl.xml", MimeType: "application/vnd.etsi.tsl+xml"},
	}}

	if _, found := list.Find("es"); !found {
		t.Error("lowercase territory did not match")
	}
}

// TestFindReportsAMissingTerritory covers the negative case.
func TestFindReportsAMissingTerritory(t *testing.T) {
	list := domain.LOTL{Entries: []domain.LOTLEntry{
		{Territory: "IT", Location: "https://example.org/tsl.xml"},
	}}

	if _, found := list.Find("ZZ"); found {
		t.Error("an absent territory was found")
	}
}
