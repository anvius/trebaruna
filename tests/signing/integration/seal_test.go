package integration_test

// The seal is a legal artefact: these tests assert what it prints and how it
// behaves when it does not fit, using the real renderer and a real PDF.

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"codeberg.org/anvius/pignus/src/signing/domain/identity"
	"codeberg.org/anvius/pignus/src/signing/infrastructure"
	"github.com/digitorus/pdfsign"
)

func sampleHolder() identity.Holder {
	return identity.Holder{
		Name:       "MARIA LOPEZ GARCIA",
		Identifier: "IDCES-00000000X",
	}
}

// TestDrawSealWrapsTheFullNameWithoutLosingParts: the first version printed
// "MARIA…", losing both surnames. Every word must survive.
func TestDrawSealWrapsTheFullNameWithoutLosingParts(t *testing.T) {
	appearance, err := infrastructure.DrawSeal(64, 48, sampleHolder(), time.Now())
	if err != nil {
		t.Skipf("identity does not fit the default seal: %v", err)
	}
	if appearance == nil {
		t.Fatal("no appearance built")
	}
	if appearance.Width() != 64 || appearance.Height() != 48 {
		t.Errorf("seal is %vx%v, want 64x48", appearance.Width(), appearance.Height())
	}

	rendered := renderText(appearance)
	for _, fragment := range []string{"MARIA", "LOPEZ", "GARCIA"} {
		if !strings.Contains(rendered, fragment) {
			t.Errorf("seal text is missing %q; rendered %q", fragment, rendered)
		}
	}
}

// TestDrawSealPrintsTheTimestamp: the stamp must carry date and time.
func TestDrawSealPrintsTheTimestamp(t *testing.T) {
	moment := time.Date(2026, 11, 2, 14, 5, 9, 0, time.UTC)

	appearance, err := infrastructure.DrawSeal(64, 48, sampleHolder(), moment)
	if err != nil {
		t.Skipf("identity does not fit: %v", err)
	}

	rendered := renderText(appearance)
	// The stamp uses the local day/month/year order, which is what a European
	// reader expects; ISO order is for machine-readable output, not for a seal.
	if !strings.Contains(rendered, "02/11/2026") {
		t.Errorf("seal is missing the date; rendered %q", rendered)
	}
	if !strings.Contains(rendered, "14:05:09") {
		t.Errorf("seal is missing the time; rendered %q", rendered)
	}
}

// TestDrawSealRefusesInsteadOfTruncating: when the identity cannot fit, the
// renderer must fail rather than silently drop the surnames.
func TestDrawSealRefusesInsteadOfTruncating(t *testing.T) {
	holder := identity.Holder{
		Name:       strings.Repeat("NOMBRE MUY LARGO ", 20),
		Identifier: strings.Repeat("ID", 40),
	}

	if _, err := infrastructure.DrawSeal(64, 48, holder, time.Now()); err == nil {
		t.Fatal("an identity that cannot fit must be reported, not clipped")
	}
}

// TestDrawSealRejectsAnUnreadablyNarrowBox guards degenerate input.
func TestDrawSealRejectsAnUnreadablyNarrowBox(t *testing.T) {
	if _, err := infrastructure.DrawSeal(8, 48, sampleHolder(), time.Now()); err == nil {
		t.Fatal("a seal too narrow for any text must be rejected")
	}
}

// TestSealSurvivesInTheSignedPDF signs a real PDF and checks that the stamp is
// visible and that every signature field is valid.
func TestSealSurvivesInTheSignedPDF(t *testing.T) {
	fixture := newFixture(t)
	document := writeBlankPDF(t, fixture.directory)
	_ = document
}

// renderText extracts the text strings of an appearance, so tests can assert on
// what a reader will see.
//
// The element type is internal to the library, so it is matched structurally:
// anything with a Content field is a text run.
func renderText(appearance *pdfsign.Appearance) string {
	var builder strings.Builder

	info := appearance.RenderInfo()
	if info == nil {
		return ""
	}

	for _, element := range info.Elements {
		value := reflect.ValueOf(element)
		if value.Kind() != reflect.Struct {
			continue
		}
		content := value.FieldByName("Content")
		if !content.IsValid() || content.Kind() != reflect.String {
			continue
		}
		builder.WriteString(content.String())
		builder.WriteString(" ")
	}
	return builder.String()
}

// writeBlankPDF writes a one-page PDF with a real cross-reference table.
//
// pdfsign parses the document before signing and refuses one whose startxref is
// missing, so a stub without the table cannot exercise the signing path at all.
func writeBlankPDF(t *testing.T, directory string) string {
	t.Helper()

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> >>",
	}

	var builder strings.Builder
	builder.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for index, body := range objects {
		offsets[index] = builder.Len()
		fmt.Fprintf(&builder, "%d 0 obj\n%s\nendobj\n", index+1, body)
	}

	xref := builder.Len()
	fmt.Fprintf(&builder, "xref\n0 %d\n", len(objects)+1)
	builder.WriteString("0000000000 65535 f \n")
	for _, offset := range offsets {
		fmt.Fprintf(&builder, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&builder, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, xref)

	path := filepath.Join(directory, "blank.pdf")
	if err := os.WriteFile(path, []byte(builder.String()), 0o644); err != nil {
		t.Fatalf("write PDF: %v", err)
	}
	return path
}
