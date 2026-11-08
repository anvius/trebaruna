package messaging_test

import (
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

func TestEveryCatalogueIsComplete(t *testing.T) {
	for _, language := range []messaging.Language{
		messaging.Spanish, messaging.Italian, messaging.English,
	} {
		catalogue := messaging.For(language)

		fields := map[string]string{
			"WindowTitle":      catalogue.WindowTitle,
			"Subtitle":         catalogue.Subtitle,
			"DocumentLabel":    catalogue.DocumentLabel,
			"CertificateLabel": catalogue.CertificateLabel,
			"PassphraseLabel":  catalogue.PassphraseLabel,
			"FormatLabel":      catalogue.FormatLabel,
			"LevelLabel":       catalogue.LevelLabel,
			"PageLabel":        catalogue.PageLabel,
			"BoxLabel":         catalogue.BoxLabel,
			"CaptionLabel":     catalogue.CaptionLabel,
			"TSALabel":         catalogue.TSALabel,
			"ResultLabel":      catalogue.ResultLabel,
			"ChooseButton":     catalogue.ChooseButton,
			"SignButton":       catalogue.SignButton,
			"SigningMessage":   catalogue.SigningMessage,
			"DoneTitle":        catalogue.DoneTitle,
			"DoneQuestion":     catalogue.DoneQuestion,
			"MissingDocument":  catalogue.MissingDocument,
			"MissingKey":       catalogue.MissingKey,
			"MissingTSA":       catalogue.MissingTSA,
			"InvalidPage":      catalogue.InvalidPage,
			"NoOutput":         catalogue.NoOutput,
		}

		for name, value := range fields {
			if value == "" {
				t.Errorf("%s.%s is empty: a missing translation must not compile silently", language, name)
			}
		}
		if catalogue.Language != language {
			t.Errorf("catalogue for %q reports language %q", language, catalogue.Language)
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
		{spanish.CertificateLabel, italian.CertificateLabel},
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

func TestDoneMessageIncludesThePath(t *testing.T) {
	spanish := messaging.For(messaging.Spanish)
	message := spanish.DoneMessage("/tmp/contratto_signed.pdf")
	if !contains(message, "/tmp/contratto_signed.pdf") {
		t.Errorf("done message must include the path, got %q", message)
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
