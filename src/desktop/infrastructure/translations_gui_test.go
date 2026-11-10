//go:build gui

package infrastructure

import (
	"testing"

	"fyne.io/fyne/v2/lang"

	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

// The translation registry is process-global and every test in this file adds
// to it, so each test sets the locale it needs and asserts what that locale
// resolves to. The one thing that cannot be undone is registration itself:
// a bundle registered by an earlier test stays registered. The assertions are
// written so that this only ever helps — a correct answer stays correct.

// TestSpanishSystemKeepsFyneTranslations pins the defect of the exact tag.
//
// Fyne ships a complete Spanish bundle under "es". Registering our short base
// under the system locale "es-ES" created an exact tag, the localizer started
// asking for "es-ES", and the chain stopped there: every string our bundle did
// not carry — "File", "file.parent" — came back in English with a log line.
// Every Spanish launch logged this until the Wayland run of the window made it
// visible.
func TestSpanishSystemKeepsFyneTranslations(t *testing.T) {
	t.Setenv("LANG", "es_ES.UTF-8")
	t.Setenv("LC_ALL", "es_ES.UTF-8")

	InstallTranslations(messaging.Spanish)

	if got := lang.LocalizeKey("File", "File"); got != "Archivo" {
		t.Errorf("File = %q, want the Spanish Fyne itself ships (Archivo)", got)
	}
	if got := lang.LocalizeKey("file.parent", "Parent"); got != "Padre" {
		t.Errorf("file.parent = %q, want Padre", got)
	}
}

// TestItalianSystemGetsItalianWidgets covers the language Fyne does not ship.
//
// The system is Italian and so is the application: the file dialog must answer
// in Italian, which means the overrides have to be registered under the system
// locale too, because a bundle registered for "it" never answers a question
// asked of "it-IT".
func TestItalianSystemGetsItalianWidgets(t *testing.T) {
	t.Setenv("LANG", "it_IT.UTF-8")
	t.Setenv("LC_ALL", "it_IT.UTF-8")

	InstallTranslations(messaging.Italian)

	if got := lang.LocalizeKey("Cancel", "Cancel"); got != "Annulla" {
		t.Errorf("Cancel = %q, want Annulla", got)
	}
	if got := lang.LocalizeKey("file.parent", "Parent"); got != "Su" {
		t.Errorf("file.parent = %q, want Su", got)
	}
	// Fyne adds a Quit item to the first menu with this word; without it an
	// Italian window ended its File menu in English.
	if got := lang.LocalizeKey("Quit", "Quit"); got != "Esci" {
		t.Errorf("Quit = %q, want Esci", got)
	}
}

// TestItalianSystemEnglishAppStaysReadable covers the remaining combination.
//
// The system is Italian and the application is English: our English base
// answers for the system locale so nothing logs "not found", and the strings
// read as English rather than as raw keys.
func TestItalianSystemEnglishAppStaysReadable(t *testing.T) {
	t.Setenv("LANG", "it_IT.UTF-8")
	t.Setenv("LC_ALL", "it_IT.UTF-8")

	InstallTranslations(messaging.English)

	if got := lang.LocalizeKey("file.parent", "Parent"); got != "Parent" {
		t.Errorf("file.parent = %q, want the readable English fallback", got)
	}
	if got := lang.LocalizeKey("File", "File"); got != "File" {
		t.Errorf("File = %q, want File", got)
	}
}

// TestFallbackCoversEveryOverrideKey keeps the two maps honest.
//
// Every key the overrides carry must exist in the base as well: on a system
// whose language Fyne ships but does not cover some key for, the base is what
// answers, and a key that is only in the overrides comes out as a raw key
// there.
func TestFallbackCoversEveryOverrideKey(t *testing.T) {
	base := englishFallback()
	for _, language := range messaging.Languages() {
		overrides := fyneTranslationsFor(language)
		for key := range overrides {
			if _, ok := base[key]; !ok {
				t.Errorf("language %v overrides %q, but the base does not carry it", language, key)
			}
		}
		// A language Fyne does not ship answers for every key, or its users
		// see English buttons next to their own labels.
		if language != messaging.English && len(overrides) != len(base) {
			t.Errorf("language %v translates %d of the %d widget strings", language, len(overrides), len(base))
		}
	}
}
