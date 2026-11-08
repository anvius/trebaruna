package domain_test

import (
	"testing"

	"codeberg.org/anvius/trebaruna/src/desktop/domain"
)

func validIntent() domain.SigningIntent {
	return domain.SigningIntent{
		DocumentPath: "/tmp/contratto.pdf",
		KeyPath:      "/tmp/mario.p12",
		Format:       "pades",
		Level:        "bes",
		Page:         1,
	}
}

func TestValidateAcceptsCompleteIntent(t *testing.T) {
	if err := validIntent().Validate(); err != nil {
		t.Fatalf("valid intent rejected: %v", err)
	}
}

func TestValidateReportsMissingDocument(t *testing.T) {
	intent := validIntent()
	intent.DocumentPath = "  "

	err := intent.Validate()
	problem, ok := err.(domain.Problem)
	if !ok || problem.Code != domain.ProblemMissingDocument {
		t.Fatalf("err = %v, want ProblemMissingDocument", err)
	}
}

func TestValidateReportsMissingKey(t *testing.T) {
	intent := validIntent()
	intent.KeyPath = ""

	err := intent.Validate()
	problem, ok := err.(domain.Problem)
	if !ok || problem.Code != domain.ProblemMissingKey {
		t.Fatalf("err = %v, want ProblemMissingKey", err)
	}
}

func TestValidateRequiresTSAForLevelT(t *testing.T) {
	intent := validIntent()
	intent.Level = "t"

	err := intent.Validate()
	problem, ok := err.(domain.Problem)
	if !ok || problem.Code != domain.ProblemMissingTSA {
		t.Fatalf("err = %v, want ProblemMissingTSA", err)
	}
}

func TestValidateAcceptsLevelTWithTSA(t *testing.T) {
	intent := validIntent()
	intent.Level = "t"
	intent.TimestampURL = "https://tsa.example/tsa"

	if err := intent.Validate(); err != nil {
		t.Fatalf("level T with a TSA rejected: %v", err)
	}
}

func TestValidateRejectsZeroPage(t *testing.T) {
	intent := validIntent()
	intent.Page = 0

	err := intent.Validate()
	problem, ok := err.(domain.Problem)
	if !ok || problem.Code != domain.ProblemInvalidPage {
		t.Fatalf("err = %v, want ProblemInvalidPage", err)
	}
}

func TestParseBox(t *testing.T) {
	box, err := domain.ParseBox("100,200,300,400")
	if err != nil {
		t.Fatalf("valid box rejected: %v", err)
	}
	if box.LowerLeftX != 100 || box.UpperRightY != 400 {
		t.Errorf("box = %+v", box)
	}
}

func TestParseBoxRejectsMalformed(t *testing.T) {
	for _, raw := range []string{"", "1,2,3", "a,b,c,d", "300,200,100,400", "100,400,300,200"} {
		if _, err := domain.ParseBox(raw); err == nil {
			t.Errorf("ParseBox(%q) must fail", raw)
		}
	}
}

func TestArgumentsTranslateToCLIFlags(t *testing.T) {
	intent := validIntent()
	intent.Level = "t"
	intent.TimestampURL = "https://tsa.example/tsa"
	intent.Box = "100,600,300,700"
	intent.Page = 2
	intent.Passphrase = "secret"
	intent.Reason = "Contratto"

	arguments := intent.Arguments()

	expected := map[string]string{
		"sign":     "/tmp/contratto.pdf",
		"--format": "pades",
		"--level":  "t",
		"--p12":    "/tmp/mario.p12",
		"--pass":   "secret",
		"--page":   "2",
		"--box":    "100,600,300,700",
		"--tsa":    "https://tsa.example/tsa",
		"--reason": "Contratto",
	}

	for flag, value := range expected {
		if !containsPair(arguments, flag, value) {
			t.Errorf("arguments missing %s %s: %v", flag, value, arguments)
		}
	}
	if !containsValue(arguments, "--json") {
		t.Error("arguments must request JSON output so the window can parse it")
	}
}

func TestArgumentsUsePemFlagForPemKeys(t *testing.T) {
	intent := validIntent()
	intent.KeyPath = "/tmp/mario.pem"

	arguments := intent.Arguments()
	if !containsPair(arguments, "--pem", "/tmp/mario.pem") {
		t.Errorf("a .pem key must use --pem: %v", arguments)
	}
	if containsValue(arguments, "--p12") {
		t.Error("a .pem key must not also pass --p12")
	}
}

func TestOutputNameFollowsTheSameConventionAsTheCLI(t *testing.T) {
	cases := []struct {
		document string
		format   string
		want     string
	}{
		{"/tmp/contratto.pdf", "pades", "/tmp/contratto_signed.pdf"},
		{"/tmp/fattura.xml", "cades", "/tmp/fattura.xml.p7m"},
		{"/tmp/atto.xml", "xades", "/tmp/atto_signed.xml"},
		{"/tmp/senza_estensione", "pades", "/tmp/senza_estensione_signed.pdf"},
	}

	for _, testCase := range cases {
		intent := validIntent()
		intent.DocumentPath = testCase.document
		intent.Format = testCase.format
		if got := intent.OutputName(); got != testCase.want {
			t.Errorf("OutputName(%q, %q) = %q, want %q",
				testCase.document, testCase.format, got, testCase.want)
		}
	}
}

func TestItalianErrorMessagesAreTranslatable(t *testing.T) {
	// The problem carries a code, never a sentence, so the window can render
	// it in the active language.
	intent := validIntent()
	intent.KeyPath = ""

	err := intent.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	if message := err.Error(); containsValue([]string{message}, "certificado") {
		t.Errorf("error carries Spanish prose instead of a code: %q", message)
	}
}

func containsPair(arguments []string, flag, value string) bool {
	for index := 0; index < len(arguments)-1; index++ {
		if arguments[index] == flag && arguments[index+1] == value {
			return true
		}
	}
	return false
}

func containsValue(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
