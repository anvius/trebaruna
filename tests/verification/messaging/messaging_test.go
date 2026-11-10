package messaging_test

// Every language of the verification report is whole: every label, every
// finding the Spanish catalogue has, the same formatting verbs, and none of
// them the Spanish one under another name.

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/verification/messaging"
)

var catalogues = map[string]messaging.Catalogue{
	"ca": messaging.Catalan, "gl": messaging.Galician, "eu": messaging.Basque,
	"it": messaging.Italian, "en": messaging.English,
}

var verbs = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z%]`)

func sameVerbs(left, right string) bool {
	return strings.Join(verbs.FindAllString(left, -1), " ") == strings.Join(verbs.FindAllString(right, -1), " ")
}

func TestEveryReportLanguageIsWhole(t *testing.T) {
	spanish := reflect.ValueOf(messaging.Spanish)
	for tag, catalogue := range catalogues {
		value := reflect.ValueOf(catalogue)
		for index := 0; index < value.NumField(); index++ {
			name := value.Type().Field(index).Name
			if value.Field(index).Kind() != reflect.String {
				continue
			}
			if text := value.Field(index).String(); text == "" || !sameVerbs(text, spanish.Field(index).String()) {
				t.Errorf("%s.%s = %q", tag, name, text)
			}
		}
		for code, text := range messaging.Spanish.Findings {
			if translated := catalogue.Findings[code]; translated == "" || !sameVerbs(translated, text) {
				t.Errorf("%s: finding %s = %q", tag, code, translated)
			}
		}
		for code, text := range messaging.Spanish.Issuers {
			if translated := catalogue.Issuers[code]; translated == "" || !sameVerbs(translated, text) {
				t.Errorf("%s: issuer note %s = %q", tag, code, translated)
			}
		}
		if catalogue.ReportTitle == messaging.Spanish.ReportTitle || catalogue.ReportNote == messaging.Spanish.ReportNote {
			t.Errorf("%s is the Spanish catalogue", tag)
		}
	}
}

func TestALocalePicksItsLanguage(t *testing.T) {
	for locale, want := range map[string]messaging.Catalogue{
		"ca_ES.UTF-8": messaging.Catalan, "GL": messaging.Galician, "eu": messaging.Basque,
		"it_IT": messaging.Italian, "en": messaging.English, "fr": messaging.Spanish, "": messaging.Spanish,
	} {
		if got := messaging.For(locale); got.ReportTitle != want.ReportTitle {
			t.Errorf("%q picks %q", locale, got.ReportTitle)
		}
	}
}

// TestTheIssuerNoteNamesTheListsTerritory: the qualified note says whose
// list; a code no language knows falls back to the verdict's own words.
func TestTheIssuerNoteNamesTheListsTerritory(t *testing.T) {
	for _, lang := range []string{"es", "it", "en", "ca", "gl", "eu"} {
		catalogue := messaging.For(lang)
		if note := catalogue.IssuerNote("issuer.qualified", "IT", "fallback"); !strings.Contains(note, "IT") || strings.Contains(note, "%") {
			t.Errorf("%s: %q", lang, note)
		}
		if note := catalogue.IssuerNote("issuer.unlisted", "IT", "fallback"); note == "fallback" || strings.Contains(note, "IT") {
			t.Errorf("%s: %q", lang, note)
		}
	}
	if note := messaging.For("es").IssuerNote("issuer.future", "IT", "the verdict's words"); note != "the verdict's words" {
		t.Errorf("an unknown code: %q", note)
	}
}
