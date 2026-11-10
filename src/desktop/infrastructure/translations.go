//go:build gui

package infrastructure

import (
	"encoding/json"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/lang"

	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

// fyneShippedLanguages are the languages Fyne's own widget bundles cover
// (v2.8.2 ships cs, de, el, en, es, fr, ja, pl, pt, ru, sv, ta, uk, zh; pt_BR
// folds into pt, zh_Hans into zh).
//
// The list decides whether this file may register anything for the system
// locale. Registering a bundle for a locale Fyne already answers for creates
// an exact tag that stops the resolution chain: a Spanish machine registers
// "es-ES", the localizer then asks for "es-ES" instead of falling back to
// Fyne's complete "es", and every string that is not in our short bundle —
// "File", "file.parent" — comes back in English with a log line. That was the
// state of every Spanish launch until it was reproduced and pinned in the
// tests below.
var fyneShippedLanguages = map[string]bool{
	"cs": true, "de": true, "el": true, "en": true, "es": true,
	"fr": true, "ja": true, "pl": true, "pt": true, "ru": true,
	"sv": true, "ta": true, "uk": true, "zh": true,
}

// InstallTranslations installs the strings Fyne's own widgets use.
//
// Fyne bundles Spanish but not Italian, Catalan, Galician or Basque (v2.8.2
// ships cs, de, el, en, es, fr, ja, pl, pt, ru, sv, ta, uk, zh). Without
// this, an Italian user would see English buttons next to Italian labels,
// which looks broken.
func InstallTranslations(language messaging.Language) {
	base := englishFallback()
	encodedBase, err := json.Marshal(base)
	if err != nil {
		return
	}
	// The base is registered under "en" only. Registering it under the system
	// locale as well is what broke Spanish: see fyneShippedLanguages.
	_ = lang.AddTranslationsForLocale(encodedBase, "en")

	system := lang.SystemLocale()
	systemBase := baseLanguage(system)

	// Only when Fyne cannot answer for the system language does our bundle
	// stand in. Fyne's own translations are more complete than ours can be,
	// and shadowing them costs every string we did not think of.
	if !fyneShippedLanguages[systemBase] {
		_ = lang.AddTranslationsForLocale(encodedBase, system)

		// When the application language is the system language, the overrides
		// must also be registered for the system locale: the exact tag just
		// registered is what the localizer will ask for, and a bundle
		// registered for "it" never answers a question asked of "it-IT".
		if language != messaging.English && baseLanguage(localeFor(language)) == systemBase {
			if encodedOverrides, err := json.Marshal(fyneTranslationsFor(language)); err == nil {
				_ = lang.AddTranslationsForLocale(encodedOverrides, system)
			}
		}
	}

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

// baseLanguage returns the language part of a locale ("es-ES" -> "es").
func baseLanguage(locale fyne.Locale) string {
	value := locale.LanguageString()
	for index := 0; index < len(value); index++ {
		if value[index] == '-' {
			return value[:index]
		}
	}
	return value
}

// localeFor maps our language onto a Fyne locale string: the same code.
func localeFor(language messaging.Language) fyne.Locale {
	return fyne.Locale(language)
}

// fyneTranslationsFor returns the widget strings Fyne needs.
//
// Only the keys the window actually reaches are provided: anything missing
// falls back to English, which is readable, instead of showing a raw key.
//
// The file-dialog keys matter only when this bundle is the one answering —
// a system language Fyne ships. On any other system Fyne's own bundle
// provides them, in more languages and with more care than belongs here.
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
			"New Folder":    "Nuova cartella",
			"Name":          "Nome",
			"Delete":        "Elimina",
			"Rename":        "Rinomina",
			"Confirm":       "Conferma",
			"Yes":           "Sì",
			"No":            "No",
			"Error":         "Errore",
			"Information":   "Informazioni",
			"Are you sure?": "Sei sicuro?",
			"File":          "File",
			"Quit":          "Esci",
			"file.name":     "Nome",
			"file.parent":   "Su",
		}
	case messaging.Catalan:
		return map[string]string{
			"(Select one)":  "(tria'n un)",
			"OK":            "D'acord",
			"Cancel":        "Cancel·la",
			"Open":          "Obre",
			"Save":          "Desa",
			"Create Folder": "Crea una carpeta",
			"New Folder":    "Carpeta nova",
			"Name":          "Nom",
			"Delete":        "Suprimeix",
			"Rename":        "Canvia el nom",
			"Confirm":       "Confirma",
			"Yes":           "Sí",
			"No":            "No",
			"Error":         "Error",
			"Information":   "Informació",
			"Are you sure?": "N'estàs segur?",
			"File":          "Fitxer",
			"Quit":          "Surt",
			"file.name":     "Nom",
			"file.parent":   "Amunt",
		}
	case messaging.Galician:
		return map[string]string{
			"(Select one)":  "(escolle un)",
			"OK":            "Aceptar",
			"Cancel":        "Cancelar",
			"Open":          "Abrir",
			"Save":          "Gardar",
			"Create Folder": "Crear cartafol",
			"New Folder":    "Novo cartafol",
			"Name":          "Nome",
			"Delete":        "Eliminar",
			"Rename":        "Cambiar o nome",
			"Confirm":       "Confirmar",
			"Yes":           "Si",
			"No":            "Non",
			"Error":         "Erro",
			"Information":   "Información",
			"Are you sure?": "Estás seguro?",
			"File":          "Ficheiro",
			"Quit":          "Saír",
			"file.name":     "Nome",
			"file.parent":   "Arriba",
		}
	case messaging.Basque:
		return map[string]string{
			"(Select one)":  "(aukeratu bat)",
			"OK":            "Ados",
			"Cancel":        "Utzi",
			"Open":          "Ireki",
			"Save":          "Gorde",
			"Create Folder": "Sortu karpeta",
			"New Folder":    "Karpeta berria",
			"Name":          "Izena",
			"Delete":        "Ezabatu",
			"Rename":        "Aldatu izena",
			"Confirm":       "Berretsi",
			"Yes":           "Bai",
			"No":            "Ez",
			"Error":         "Errorea",
			"Information":   "Informazioa",
			"Are you sure?": "Ziur zaude?",
			"File":          "Fitxategia",
			"Quit":          "Irten",
			"file.name":     "Izena",
			"file.parent":   "Gora",
		}
	case messaging.Polish:
		// Fyne ships Polish, but without its own case Polish fell through to
		// the Spanish below, registered under "pl" over Fyne's bundle. These
		// are Fyne's words where they are right ("Nawza", "Potwierdz",
		// "Wyjdz" and "Rodzic" are not) plus the keys its bundle lacks.
		return map[string]string{
			"(Select one)":  "(wybierz)",
			"OK":            "OK",
			"Cancel":        "Anuluj",
			"Open":          "Otwórz",
			"Save":          "Zapisz",
			"Create Folder": "Utwórz folder",
			"New Folder":    "Nowy folder",
			"Name":          "Nazwa",
			"Delete":        "Usuń",
			"Rename":        "Zmień nazwę",
			"Confirm":       "Potwierdź",
			"Yes":           "Tak",
			"No":            "Nie",
			"Error":         "Błąd",
			"Information":   "Informacja",
			"Are you sure?": "Czy na pewno?",
			"File":          "Plik",
			"Quit":          "Zakończ",
			"file.name":     "Nazwa",
			"file.parent":   "W górę",
		}
	case messaging.English:
		return map[string]string{}
	default: // Spanish. Fyne ships it; this stands in only if that ever changes.
		return map[string]string{
			"(Select one)":  "(elige uno)",
			"OK":            "OK",
			"Cancel":        "Cancelar",
			"Open":          "Abrir",
			"Save":          "Guardar",
			"Create Folder": "Crear carpeta",
			"New Folder":    "Nueva carpeta",
			"Name":          "Nombre",
			"Delete":        "Eliminar",
			"Rename":        "Cambiar nombre",
			"Confirm":       "Confirmar",
			"Yes":           "Sí",
			"No":            "No",
			"Error":         "Error",
			"Information":   "Información",
			"Are you sure?": "¿Estás seguro?",
			"File":          "Archivo",
			"Quit":          "Salir",
			"file.name":     "Nombre",
			"file.parent":   "Padre",
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
		"New Folder":    "New Folder",
		"Name":          "Name",
		"Delete":        "Delete",
		"Rename":        "Rename",
		"Confirm":       "Confirm",
		"Yes":           "Yes",
		"No":            "No",
		"Error":         "Error",
		"Information":   "Information",
		"Are you sure?": "Are you sure?",
		"File":          "File",
		"Quit":          "Quit",
		"file.name":     "Name",
		"file.parent":   "Parent",
	}
}
