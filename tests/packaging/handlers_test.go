package packaging_test

import (
	"os"
	"strings"
	"testing"
)

// TestTheDesktopEntryOffersTrebarunaForAfirmaLinks: the entry declares the
// scheme and passes the URI to the window, which opens the approval window.
func TestTheDesktopEntryOffersTrebarunaForAfirmaLinks(t *testing.T) {
	entry, err := os.ReadFile("../../packaging/trebaruna.desktop")
	if err != nil {
		t.Fatal(err)
	}
	text := string(entry)
	if !strings.Contains(text, "x-scheme-handler/afirma;") || !strings.Contains(text, "x-scheme-handler/trebaruna;") {
		t.Error("the entry must declare both schemes")
	}
	if !strings.Contains(text, "Exec=trebaruna-desktop %U") {
		t.Error("the URI must reach the window as its argument")
	}
}

// TestTheMacBundleDeclaresTheAfirmaScheme.
func TestTheMacBundleDeclaresTheAfirmaScheme(t *testing.T) {
	plist, err := os.ReadFile("../../packaging/macos/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plist), "<string>afirma</string>") {
		t.Error("the bundle must declare the afirma scheme")
	}
}
