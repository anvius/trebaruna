package messaging_test

import (
	"fmt"
	"reflect"
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
	for _, language := range []messaging.Language{
		messaging.Spanish, messaging.Italian, messaging.English,
	} {
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
	for _, language := range []messaging.Language{messaging.Spanish, messaging.Italian, messaging.English} {
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
