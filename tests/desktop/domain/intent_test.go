package domain_test

import (
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

func validIntent() domain.SigningIntent {
	return domain.SigningIntent{
		DocumentPath: "/tmp/contratto.pdf",
		Key:          domain.CertificateFile{Path: "/tmp/mario.p12"},
		Format:       "pades",
		Level:        "bes",
		Seal:         domain.SealChoice{Page: 1},
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
	intent.Key.Path = ""

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
	intent.Seal.Page = 0

	err := intent.Validate()
	problem, ok := err.(domain.Problem)
	if !ok || problem.Code != domain.ProblemInvalidPage {
		t.Fatalf("err = %v, want ProblemInvalidPage", err)
	}
}

func TestASealWithoutRectangleIsLeftToTheSigner(t *testing.T) {
	if (domain.SealChoice{Page: 1}).Placed() {
		t.Error("a choice without a rectangle must not claim a placement")
	}
	placed := domain.SealChoice{Page: 2, Rect: domain.SealRect{LowerLeftX: 10, LowerLeftY: 10, UpperRightX: 74, UpperRightY: 58}}
	if !placed.Placed() {
		t.Error("a choice with an area is a placement")
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
		{"/tmp/fattura.xml", "cades-detached", "/tmp/fattura.xml.p7s"},
		{"/tmp/atto.pdf.p7m", "cosign", "/tmp/atto.pdf_cosigned.p7m"},
		{"/tmp/atto.pdf.p7m", "countersign", "/tmp/atto.pdf_countersigned.p7m"},
		{"/tmp/atto.xml", "xades", "/tmp/atto_signed.xml"},
		{"/tmp/senza_estensione", "pades", "/tmp/senza_estensione_signed.pdf"},
	}

	for _, testCase := range cases {
		intent := validIntent()
		intent.DocumentPath = testCase.document
		intent.Format = domain.SignatureFormat(testCase.format)
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
	intent.Key.Path = ""

	err := intent.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	if message := err.Error(); containsValue([]string{message}, "certificado") {
		t.Errorf("error carries Spanish prose instead of a code: %q", message)
	}
}

func containsValue(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// TestAnOfficeDocumentIsSignedInsideItselfFirst, named like the signer
// names it.
func TestAnOfficeDocumentIsSignedInsideItselfFirst(t *testing.T) {
	for _, path := range []string{"/tmp/acta.docx", "/tmp/cuentas.XLSX", "/tmp/charla.pptx"} {
		if formats := domain.FormatsFor(path); len(formats) == 0 || formats[0] != domain.FormatOOXML {
			t.Errorf("formats for %s: %v", path, formats)
		}
	}
	intent := domain.SigningIntent{DocumentPath: "/tmp/acta.docx", Format: domain.FormatOOXML}
	if got := intent.OutputName(); got != "/tmp/acta_signed.docx" {
		t.Errorf("output %q", got)
	}
}

// TestAnOpenDocumentIsSignedInsideItselfFirst, named like the signer names it.
func TestAnOpenDocumentIsSignedInsideItselfFirst(t *testing.T) {
	formats := domain.FormatsFor("/tmp/acta.odt")
	if len(formats) == 0 || formats[0] != domain.FormatODF {
		t.Fatalf("formats for an ODT: %v", formats)
	}
	intent := domain.SigningIntent{DocumentPath: "/tmp/acta.odt", Format: domain.FormatODF}
	if got := intent.OutputName(); got != "/tmp/acta_signed.odt" {
		t.Errorf("output %q", got)
	}
}

// TestAnEnvelopeIsKnownByItsSuffix: .p7e in any case, nothing else.
func TestAnEnvelopeIsKnownByItsSuffix(t *testing.T) {
	for path, want := range map[string]bool{
		"/tmp/offerta.pdf.p7e": true, "/tmp/OFFERTA.P7E": true, "/tmp/offerta.p7m": false, "/tmp/p7e.pdf": false,
	} {
		if got := domain.IsEnvelope(path); got != want {
			t.Errorf("%s: %v", path, got)
		}
	}
}
