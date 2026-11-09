package messaging_test

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

func TestParseLanguageAcceptsLocaleStrings(t *testing.T) {
	cases := map[string]messaging.Language{
		"it":          messaging.Italian,
		"it_IT.UTF-8": messaging.Italian,
		"it-IT":       messaging.Italian,
		"es":          messaging.Spanish,
		"es_ES.UTF-8": messaging.Spanish,
		"en_GB":       messaging.English,
		"ca_ES.UTF-8": messaging.Catalan,
		"gl_ES":       messaging.Galician,
		"eu_ES.UTF-8": messaging.Basque,
		"":            messaging.Spanish,
		"fr_FR":       messaging.Spanish,
	}

	for raw, want := range cases {
		if got := messaging.ParseLanguage(raw); got != want {
			t.Errorf("ParseLanguage(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestEveryCatalogueIsComplete walks every string field by reflection, so a
// field added to one language and forgotten in another fails here instead of
// showing an empty label in the window.
func TestEveryCatalogueIsComplete(t *testing.T) {
	for _, language := range messaging.Languages() {
		catalogue := messaging.For(language)
		value := reflect.ValueOf(catalogue)
		for index := 0; index < value.NumField(); index++ {
			field := value.Type().Field(index)
			if field.Type.Kind() != reflect.String {
				continue
			}
			if value.Field(index).String() == "" {
				t.Errorf("%s.%s is empty: a missing translation must not ship silently", language, field.Name)
			}
		}
		if catalogue.Language != language {
			t.Errorf("catalogue for %q reports language %q", language, catalogue.Language)
		}
	}
}

func TestFormatStringsKeepTheirPlaceholders(t *testing.T) {
	for _, language := range messaging.Languages() {
		catalogue := messaging.For(language)
		if got := fmt.Sprintf(catalogue.PageOf, 2, 5); !contains(got, "2") || !contains(got, "5") {
			t.Errorf("%s PageOf renders %q, want both numbers", language, got)
		}
	}
}

func TestItalianAndSpanishDiffer(t *testing.T) {
	// A copy-paste error that leaves Spanish strings in the Italian catalogue
	// would be invisible in a single-language test.
	spanish := messaging.For(messaging.Spanish)
	italian := messaging.For(messaging.Italian)

	// Note: "Documento" is legitimately identical in both languages, so the
	// comparison uses strings that must differ.
	pairs := [][2]string{
		{spanish.SignButton, italian.SignButton},
		{spanish.CertificateLocked, italian.CertificateLocked},
		{spanish.WindowTitle, italian.WindowTitle},
		{spanish.MissingDocument, italian.MissingDocument},
	}
	for _, pair := range pairs {
		if pair[0] == pair[1] {
			t.Errorf("the same string appears in both catalogues: %q", pair[0])
		}
	}
}

// verbs are the formatting verbs of a string, in order.
var verbs = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z%]`)

// TestEveryTranslationKeepsTheVerbsOfTheSpanish: a translated string that
// loses a %s or swaps a %d for a %s prints garbage at run time.
func TestEveryTranslationKeepsTheVerbsOfTheSpanish(t *testing.T) {
	spanish := reflect.ValueOf(messaging.For(messaging.Spanish))
	for _, language := range messaging.Languages() {
		value := reflect.ValueOf(messaging.For(language))
		for index := 0; index < value.NumField(); index++ {
			if value.Field(index).Kind() != reflect.String {
				continue
			}
			want := strings.Join(verbs.FindAllString(spanish.Field(index).String(), -1), " ")
			if got := strings.Join(verbs.FindAllString(value.Field(index).String(), -1), " "); got != want {
				t.Errorf("%s.%s has verbs %q, the Spanish %q", language, value.Type().Field(index).Name, got, want)
			}
		}
	}
}

// TestEveryLanguageIsTranslated: no catalogue is the Spanish one under
// another name.
func TestEveryLanguageIsTranslated(t *testing.T) {
	spanish := messaging.For(messaging.Spanish)
	for _, language := range messaging.Languages()[1:] {
		catalogue := messaging.For(language)
		same := 0
		for _, pair := range [][2]string{
			{spanish.SignButton, catalogue.SignButton}, {spanish.MissingDocument, catalogue.MissingDocument},
			{spanish.CertificateLocked, catalogue.CertificateLocked}, {spanish.SealHint, catalogue.SealHint},
			{spanish.VerifyHint, catalogue.VerifyHint}, {spanish.RubricHint, catalogue.RubricHint},
		} {
			if pair[0] == pair[1] {
				same++
			}
		}
		if same > 1 {
			t.Errorf("%s repeats %d Spanish strings out of 6", language, same)
		}
	}
}

func TestMissingTSAMessageNamesTheLevel(t *testing.T) {
	italian := messaging.For(messaging.Italian)
	message := italian.MissingTSAMessage("t")
	if message == "" {
		t.Fatal("empty message")
	}
	if !contains(message, "T") {
		t.Errorf("message must name the level, got %q", message)
	}
}

func contains(haystack, needle string) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}
