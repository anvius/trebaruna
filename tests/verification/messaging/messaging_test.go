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
