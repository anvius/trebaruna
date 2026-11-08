//go:build gui

package infrastructure

import (
	"encoding/json"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/lang"

	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

// InstallTranslations installs the strings Fyne's own widgets use.
//
// Fyne bundles Spanish but not Italian (v2.8.2 ships cs, de, el, en, es, fr, ja,
// pl, pt, ru, sv, ta, uk, zh). Without this, an Italian user would see English
// buttons next to Italian labels, which looks broken.
func InstallTranslations(language messaging.Language) {
	// Fyne resolves every widget string against the OS locale, not against the
	// language the application asked for. The base bundle therefore has to be
	// registered for the system locale as well, or Spanish machines keep
	// logging "not found in language es" while the Italian bundle sits unused.
	base := englishFallback()
	encodedBase, err := json.Marshal(base)
	if err != nil {
		return
	}
	_ = lang.AddTranslationsForLocale(encodedBase, "en")
	_ = lang.AddTranslationsForLocale(encodedBase, lang.SystemLocale())

	if language == messaging.English {
		return
	}

	// The active language overrides the base for its own locale.
	overrides := fyneTranslationsFor(language)
	encodedOverrides, err := json.Marshal(overrides)
	if err != nil {
		return
	}
	_ = lang.AddTranslationsForLocale(encodedOverrides, localeFor(language))
}

// localeFor maps our language onto a Fyne locale string.
func localeFor(language messaging.Language) fyne.Locale {
	switch language {
	case messaging.Italian:
		return "it"
	case messaging.English:
		return "en"
	default:
		return "es"
	}
}

// fyneTranslationsFor returns the widget strings Fyne needs.
//
// Only the keys the window actually reaches are provided: anything missing
// falls back to English, which is readable, instead of showing a raw key.
func fyneTranslationsFor(language messaging.Language) map[string]string {
	switch language {
	case messaging.Italian:
		return map[string]string{
			"(Select one)":  "(scegli)",
			"OK":            "OK",
			"Cancel":        "Annulla",
			"Open":          "Apri",
			"Save":          "Salva",
			"Create Folder": "Crea cartella",
			"Name":          "Nome",
			"Delete":        "Elimina",
			"Rename":        "Rinomina",
			"Confirm":       "Conferma",
			"Yes":           "Sì",
			"No":            "No",
			"Error":         "Errore",
			"Information":   "Informazioni",
			"Are you sure?": "Sei sicuro?",
		}
	case messaging.English:
		return map[string]string{}
	default:
		return map[string]string{
			"(Select one)": "(elige uno)",
		}
	}
}

// englishFallback is the base bundle Fyne falls back to.
func englishFallback() map[string]string {
	return map[string]string{
		"(Select one)":  "(Select one)",
		"OK":            "OK",
		"Cancel":        "Cancel",
		"Open":          "Open",
		"Save":          "Save",
		"Create Folder": "Create Folder",
		"Name":          "Name",
		"Delete":        "Delete",
		"Rename":        "Rename",
		"Confirm":       "Confirm",
		"Yes":           "Yes",
		"No":            "No",
		"Error":         "Error",
		"Information":   "Information",
		"Are you sure?": "Are you sure?",
	}
}

// describeLanguages is used by the tests to assert both catalogues are whole.
func describeLanguages() string {
	return fmt.Sprintf("%s,%s,%s", messaging.Spanish, messaging.Italian, messaging.English)
}
