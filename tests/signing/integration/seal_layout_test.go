package integration_test

// Layout tests for the seal. They exist because the first design truncated a
// surname and the second split a date across two lines; both were only visible
// by rendering a PDF and looking at it.

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain/identity"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// TestSealKeepsTheWholeNameInTwoLines checks that a long name wraps instead of
// being abbreviated.
func TestSealKeepsTheWholeNameInTwoLines(t *testing.T) {
	holder := identity.Holder{Name: "MARIA LOPEZ GARCIA MARTINEZ", Identifier: "IDCES-00000000X"}

	appearance, err := infrastructure.DrawSeal(64, 48, holder, sampleMoment())
	if err != nil {
		t.Fatalf("DrawSeal: %v", err)
	}

	rendered := renderText(appearance)
	for _, word := range []string{"MARIA", "LOPEZ", "GARCIA", "MARTINEZ"} {
		if !strings.Contains(rendered, word) {
			t.Errorf("seal dropped %q; rendered %q", word, rendered)
		}
	}
	if strings.Contains(rendered, "…") {
		t.Errorf("the seal abbreviated the name: %q", rendered)
	}
}

// TestSealKeepsDateOnOneLine is the regression guard for "2026-" / "11-02".
func TestSealKeepsDateOnOneLine(t *testing.T) {
	holder := identity.Holder{Name: "Maria Lopez", Identifier: "IDCES-00000000X"}

	appearance, err := infrastructure.DrawSeal(64, 48, holder, sampleMoment())
	if err != nil {
		t.Fatalf("DrawSeal: %v", err)
	}

	rendered := renderText(appearance)
	if !strings.Contains(rendered, "02/11/2026") {
		t.Errorf("the date was split or missing: %q", rendered)
	}
	for _, fragment := range []string{"2026-\n", "11-02"} {
		if strings.Contains(rendered, fragment) {
			t.Errorf("date broken across lines (%q): %q", fragment, rendered)
		}
	}
}

// TestSealShowsTheTimeWithOffset: without the offset a reader cannot tell which
// timezone the signature refers to.
func TestSealShowsTheTimeWithOffset(t *testing.T) {
	appearance, err := infrastructure.DrawSeal(64, 48,
		identity.Holder{Name: "Maria Lopez", Identifier: "IDCES-00000000X"}, sampleMoment())
	if err != nil {
		t.Fatalf("DrawSeal: %v", err)
	}

	rendered := renderText(appearance)
	if !strings.Contains(rendered, "14:05:09") {
		t.Errorf("time missing: %q", rendered)
	}
	if !strings.Contains(rendered, "+01:00") && !strings.Contains(rendered, "+00:00") {
		t.Errorf("time offset missing: %q", rendered)
	}
}

// TestSealScalesWithTheBox: a larger box must not produce a tiny stamp floating
// in white space.
func TestSealScalesWithTheBox(t *testing.T) {
	holder := identity.Holder{Name: "Maria Lopez", Identifier: "IDCES-00000000X"}

	small, err := infrastructure.DrawSeal(64, 48, holder, sampleMoment())
	if err != nil {
		t.Fatalf("small seal: %v", err)
	}
	large, err := infrastructure.DrawSeal(120, 90, holder, sampleMoment())
	if err != nil {
		t.Fatalf("large seal: %v", err)
	}

	if small.Width() != 64 || small.Height() != 48 {
		t.Errorf("small seal is %vx%v", small.Width(), small.Height())
	}
	if large.Width() != 120 || large.Height() != 90 {
		t.Errorf("large seal is %vx%v", large.Width(), large.Height())
	}
	// The large stamp must carry more than one line of detail, which only
	// happens when the type scale follows the box.
	if len(renderText(large)) <= len(renderText(small))/2 {
		t.Error("the large seal did not use the extra space")
	}
}

// TestSealRejectsAnImpossibleBox: better a clear error than a blank stamp.
func TestSealRejectsAnImpossibleBox(t *testing.T) {
	holder := identity.Holder{Name: "Maria Lopez", Identifier: "IDCES-00000000X"}

	for _, size := range [][2]float64{{0, 48}, {64, 0}, {-10, 48}, {12, 48}} {
		if _, err := infrastructure.DrawSeal(size[0], size[1], holder, sampleMoment()); err == nil {
			t.Errorf("DrawSeal(%v, %v) must fail", size[0], size[1])
		}
	}
}

// TestSealRefusesRatherThanTruncatingLongIdentities keeps the promise that no
// part of the identity is silently dropped.
func TestSealRefusesRatherThanTruncatingLongIdentities(t *testing.T) {
	holder := identity.Holder{
		Name:       strings.Repeat("NOMBRE COMPUESTO MUY LARGO ", 12),
		Identifier: strings.Repeat("ID", 60),
	}

	if _, err := infrastructure.DrawSeal(64, 48, holder, sampleMoment()); err == nil {
		t.Fatal("an identity that cannot fit must be reported")
	}
}

// TestSealWithoutIdentifierStillRenders: a plain certificate has no serialNumber.
func TestSealWithoutIdentifierStillRenders(t *testing.T) {
	appearance, err := infrastructure.DrawSeal(64, 48,
		identity.Holder{Name: "Maria Lopez"}, sampleMoment())
	if err != nil {
		t.Fatalf("DrawSeal: %v", err)
	}

	rendered := renderText(appearance)
	if !strings.Contains(rendered, "Maria Lopez") || !strings.Contains(rendered, "02/11/2026") {
		t.Errorf("incomplete seal: %q", rendered)
	}
}

// sampleMoment is a fixed instant with a non-UTC offset, which is the case that
// exposes missing offset handling.
func sampleMoment() time.Time {
	zone := time.FixedZone("CET", 3600)
	return time.Date(2026, 11, 2, 14, 5, 9, 0, zone)
}

// TestSealNeverOverprintsAWrappedName is the regression guard for details
// drawn at a fixed height: with a name of two or more lines the identifier and
// the date landed on top of the second name line. Every text line must sit
// below the previous one by at least most of its own size.
func TestSealNeverOverprintsAWrappedName(t *testing.T) {
	holder := identity.Holder{Name: "MARIA DEL CARMEN LOPEZ GARCIA MARTINEZ", Identifier: "IDCES-00000000X"}

	appearance, err := infrastructure.DrawSeal(64, 48, holder, sampleMoment())
	if err != nil {
		t.Fatalf("DrawSeal: %v", err)
	}

	type line struct {
		text    string
		y, size float64
	}
	var lines []line
	for _, element := range appearance.RenderInfo().Elements {
		value := reflect.ValueOf(element)
		if value.Kind() != reflect.Struct || !value.FieldByName("Content").IsValid() {
			continue
		}
		lines = append(lines, line{
			text: value.FieldByName("Content").String(),
			y:    value.FieldByName("Y").Float(),
			size: value.FieldByName("Size").Float(),
		})
	}
	if len(lines) < 4 {
		t.Fatalf("got %d lines, want a wrapped name plus details", len(lines))
	}
	for index := 1; index < len(lines); index++ {
		previous, current := lines[index-1], lines[index]
		if previous.y-current.y < current.size*0.8 {
			t.Errorf("%q (baseline %.1f) overprints %q (baseline %.1f)",
				current.text, current.y, previous.text, previous.y)
		}
	}
	for _, current := range lines {
		if current.y < 0 {
			t.Errorf("%q falls below the seal (baseline %.1f)", current.text, current.y)
		}
	}
}

// TestSealPrintsItsColoursAndRule guards two silent losses in pdfsign v1.0.0:
// Position() freezes a text element, so a colour set after it is dropped and
// every line came out pure black; and DrawRect() registers a type the renderer
// does not draw, so the accent rule never reached the PDF.
func TestSealPrintsItsColoursAndRule(t *testing.T) {
	holder := identity.Holder{Name: "MARIO ROSSI", Identifier: "TINIT-RSSMRA80A01H501U"}

	appearance, err := infrastructure.DrawSeal(64, 48, holder, sampleMoment())
	if err != nil {
		t.Fatalf("DrawSeal: %v", err)
	}

	type rgb struct{ r, g, b uint64 }
	colourOf := func(value reflect.Value) rgb {
		return rgb{value.FieldByName("R").Uint(), value.FieldByName("G").Uint(), value.FieldByName("B").Uint()}
	}

	var texts []rgb
	rule := false
	for _, element := range appearance.RenderInfo().Elements {
		value := reflect.ValueOf(element)
		if value.Kind() != reflect.Struct {
			continue
		}
		switch value.Type().Name() {
		case "TextElement":
			texts = append(texts, colourOf(value.FieldByName("Color")))
		case "LineElement":
			if colourOf(value.FieldByName("StrokeColor")) == (rgb{38, 84, 124}) && value.FieldByName("StrokeWidth").Float() > 1 {
				rule = true
			}
		}
	}

	if !rule {
		t.Error("the accent rule is not among the elements the renderer draws")
	}
	if len(texts) < 3 {
		t.Fatalf("got %d text lines", len(texts))
	}
	if texts[0] != (rgb{16, 20, 26}) {
		t.Errorf("name colour = %v, want 16,20,26", texts[0])
	}
	if texts[len(texts)-1] != (rgb{78, 86, 96}) {
		t.Errorf("detail colour = %v, want the grey 78,86,96", texts[len(texts)-1])
	}
}
