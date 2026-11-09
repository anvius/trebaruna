package infrastructure_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"

	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
)

// fakeCommand writes an executable that stands in for trebaruna: it records its
// arguments one per line and then runs the given shell body.
func fakeCommand(t *testing.T, body string) (binary, argumentsFile string) {
	t.Helper()
	directory := t.TempDir()
	argumentsFile = filepath.Join(directory, "arguments")
	binary = filepath.Join(directory, "trebaruna")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argumentsFile + "\n" + body + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return binary, argumentsFile
}

func recordedArguments(t *testing.T, path string) []string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(content)), "\n")
}

func fullIntent() domain.SigningIntent {
	return domain.SigningIntent{
		DocumentPath: "/tmp/contratto.pdf",
		Key:          domain.CertificateFile{Path: "/tmp/mario.p12", Passphrase: "secret"},
		Format:       "pades",
		Level:        "t",
		Seal: domain.SealChoice{Page: 2, Rect: domain.SealRect{
			LowerLeftX: 100, LowerLeftY: 600, UpperRightX: 300, UpperRightY: 700,
		}},
		TimestampURL: "https://tsa.example/tsa",
		Reason:       "Contratto",
		Location:     "Roma",
	}
}

const receiptJSON = `{"path":"/tmp/contratto_signed.pdf","standard":"PAdES-B-T","signer":"MARIO ROSSI",` +
	`"signed_at":"2026-11-09T10:00:00+01:00","seal_count":1,"self_signed":true,` +
	`"network":[{"purpose":"timestamp","method":"POST","url":"https://tsa.example/tsa","status":200}]}`

func TestTheIntentBecomesTheCommandsFlags(t *testing.T) {
	binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), fullIntent()); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	arguments := recordedArguments(t, recorded)
	expected := map[string]string{
		"sign":       "/tmp/contratto.pdf",
		"--format":   "pades",
		"--level":    "t",
		"--p12":      "/tmp/mario.p12",
		"--page":     "2",
		"--box":      "100.0,600.0,300.0,700.0",
		"--tsa":      "https://tsa.example/tsa",
		"--reason":   "Contratto",
		"--location": "Roma",
	}
	for flag, value := range expected {
		if !containsPair(arguments, flag, value) {
			t.Errorf("arguments missing %s %s: %v", flag, value, arguments)
		}
	}
	if !contains(arguments, "--json") {
		t.Error("the window parses the receipt, so --json is mandatory")
	}
}

func TestAPemKeyUsesThePemFlag(t *testing.T) {
	binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")
	intent := fullIntent()
	intent.Key.Path = "/tmp/mario.PEM"

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	arguments := recordedArguments(t, recorded)
	if !containsPair(arguments, "--pem", "/tmp/mario.PEM") || contains(arguments, "--p12") {
		t.Errorf("a .pem key must travel as --pem only: %v", arguments)
	}
}

func TestOptionalFlagsStayOffWhenEmpty(t *testing.T) {
	binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")
	intent := domain.SigningIntent{DocumentPath: "/tmp/a.pdf", Key: domain.CertificateFile{Path: "/tmp/k.p12"}, Format: "pades", Level: "bes", Seal: domain.SealChoice{Page: 1}}

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, flag := range []string{"--page", "--box", "--tsa", "--reason", "--location", "--pass", "--rubric"} {
		if contains(recordedArguments(t, recorded), flag) {
			t.Errorf("%s must not be sent when the intent leaves it empty", flag)
		}
	}
}

// TestARubricTravelsWithAVisiblePDFSealOnly.
func TestARubricTravelsWithAVisiblePDFSealOnly(t *testing.T) {
	for name, change := range map[string]func(*domain.SigningIntent){
		"visible PAdES": func(*domain.SigningIntent) {},
		"invisible":     func(intent *domain.SigningIntent) { intent.Invisible = true },
		"envelope":      func(intent *domain.SigningIntent) { intent.Format = domain.FormatCAdES },
	} {
		binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")
		intent := fullIntent()
		intent.RubricPath = "/tmp/firma.png"
		change(&intent)
		if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if sent := containsPair(recordedArguments(t, recorded), "--rubric", "/tmp/firma.png"); sent != (name == "visible PAdES") {
			t.Errorf("%s: --rubric sent %t", name, sent)
		}
	}
}

func TestTheReceiptIsReadFromTheCommandOutput(t *testing.T) {
	binary, _ := fakeCommand(t, "echo '"+receiptJSON+"'")

	receipt, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), fullIntent())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	want := domain.Receipt{
		SignedPath: "/tmp/contratto_signed.pdf", Standard: "PAdES-B-T", Signer: "MARIO ROSSI",
		SignedAt: "2026-11-09T10:00:00+01:00", SealCount: 1, SelfSigned: true,
		Network: []transparencydomain.Connection{{Purpose: "timestamp", Method: "POST", URL: "https://tsa.example/tsa", Status: 200}},
	}
	if !reflect.DeepEqual(receipt, want) {
		t.Errorf("receipt = %+v, want %+v", receipt, want)
	}
}

func TestAFailureCarriesTheCommandsExplanation(t *testing.T) {
	binary, _ := fakeCommand(t, "echo 'signing failed: timestamp: dial tcp: connection refused' >&2; exit 1")

	_, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), fullIntent())
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v, want the command's stderr line", err)
	}
}

func TestASilentFailureFallsBackToTheExitStatus(t *testing.T) {
	binary, _ := fakeCommand(t, "exit 3")

	_, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), fullIntent())
	if err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("err = %v, want the exit status when nothing was printed", err)
	}
}

func TestAnUnreadableReceiptIsAnError(t *testing.T) {
	binary, _ := fakeCommand(t, "echo 'signed /tmp/x.pdf'")

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), fullIntent()); err == nil {
		t.Fatal("plain text where JSON was requested must not pass as a receipt")
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

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestThePassphraseNeverAppearsOnTheCommandLine(t *testing.T) {
	directory := t.TempDir()
	seen := filepath.Join(directory, "environment")
	binary, recorded := fakeCommand(t, "printf '%s' \"$TREBARUNA_PASSPHRASE\" > "+seen+"; echo '"+receiptJSON+"'")

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), fullIntent()); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, argument := range recordedArguments(t, recorded) {
		if argument == "--pass" || argument == "secret" {
			t.Fatalf("the passphrase leaked into the command line: %v", recordedArguments(t, recorded))
		}
	}
	got, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Errorf("TREBARUNA_PASSPHRASE = %q, want the passphrase", got)
	}
}

func TestTheTimestampAccountTravelsWithoutItsPasswordOnTheCommandLine(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "environment")
	binary, recorded := fakeCommand(t, "printf '%s' \"$TREBARUNA_TSA_PASS\" > "+seen+"; echo '"+receiptJSON+"'")
	intent := fullIntent()
	intent.TimestampUser = "studio.rossi"
	intent.TimestampPassword = "tsa-segreta"

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	arguments := recordedArguments(t, recorded)
	if !containsPair(arguments, "--tsa-user", "studio.rossi") {
		t.Errorf("arguments = %v, want --tsa-user", arguments)
	}
	if contains(arguments, "tsa-segreta") || contains(arguments, "--tsa-pass") {
		t.Errorf("the TSA password leaked into the command line: %v", arguments)
	}
	if got, _ := os.ReadFile(seen); string(got) != "tsa-segreta" {
		t.Errorf("TREBARUNA_TSA_PASS = %q", got)
	}
}

func TestAnInvisibleSignatureSendsNoSeal(t *testing.T) {
	binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")
	intent := fullIntent()
	intent.Invisible = true

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	arguments := recordedArguments(t, recorded)
	if !contains(arguments, "--invisible") || contains(arguments, "--box") || contains(arguments, "--page") {
		t.Errorf("arguments = %v", arguments)
	}
}

func TestADetachedFormatAsksTheCommandForADetachedCAdES(t *testing.T) {
	binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")
	intent := fullIntent()
	intent.Format = domain.FormatCAdESDetached

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	arguments := recordedArguments(t, recorded)
	if !containsPair(arguments, "--format", "cades") || !contains(arguments, "--detached") {
		t.Errorf("arguments = %v", arguments)
	}
}

func TestAddedSignaturesBecomeTheCommandsOptions(t *testing.T) {
	cases := []struct {
		document string
		format   domain.SignatureFormat
		want     []string
	}{
		{"/tmp/atto.pdf.p7m", domain.FormatCosign, []string{"--cosign"}},
		{"/tmp/offerta.txt.p7s", domain.FormatCosign, []string{"--cosign", "--content", "/tmp/offerta.txt"}},
		{"/tmp/atto.pdf.p7m", domain.FormatCountersign, []string{"--countersign", "leaves"}},
	}
	for _, testCase := range cases {
		binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")
		intent := fullIntent()
		intent.DocumentPath, intent.Format = testCase.document, testCase.format
		if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		arguments := strings.Join(recordedArguments(t, recorded), " ")
		if !strings.Contains(arguments, "--format cades") || !strings.Contains(arguments, strings.Join(testCase.want, " ")) {
			t.Errorf("%s %s: arguments %q, want %v", testCase.document, testCase.format, arguments, testCase.want)
		}
	}
}

// TestAFormFieldIsSignedInPlaceOfAPlacedSeal: --field, no page nor box.
func TestAFormFieldIsSignedInPlaceOfAPlacedSeal(t *testing.T) {
	binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")
	intent := fullIntent()
	intent.Field = "form.Firma1"
	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	arguments := recordedArguments(t, recorded)
	if !containsPair(arguments, "--field", "form.Firma1") || slicesContain(arguments, "--box") || slicesContain(arguments, "--page") {
		t.Errorf("%v", arguments)
	}
}

func slicesContain(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// TestTheFormFieldsAreReadFromTheFieldsCommand.
func TestTheFormFieldsAreReadFromTheFieldsCommand(t *testing.T) {
	binary, recorded := fakeCommand(t, `echo '{"path":"/tmp/f.pdf","fields":[{"name":"Firma1","page":2,"box":[500,160,300,100]}]}'`)
	fields, err := (infrastructure.CommandLineFormFields{BinaryPath: binary}).EmptyFields(context.Background(), "/tmp/f.pdf")
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.FormField{{Name: "Firma1", Page: 2, Rect: domain.SealRect{LowerLeftX: 300, LowerLeftY: 100, UpperRightX: 500, UpperRightY: 160}}}
	if !reflect.DeepEqual(fields, want) || !reflect.DeepEqual(recordedArguments(t, recorded), []string{"fields", "/tmp/f.pdf", "--json"}) {
		t.Errorf("%+v", fields)
	}
	for _, body := range []string{"echo 'not json'", "echo 'not a PDF' >&2; exit 2"} {
		failing, _ := fakeCommand(t, body)
		if _, err := (infrastructure.CommandLineFormFields{BinaryPath: failing}).EmptyFields(context.Background(), "/tmp/f.pdf"); err == nil {
			t.Errorf("%s: no error", body)
		}
	}
}

// TestContainersInvoicesAndPoliciesBecomeFlags: an ASiC-S of one document,
// an ASiC-E of several under one signature, a FacturaE invoice with its
// policy and role, and a policy declared by a PDF signature.
func TestContainersInvoicesAndPoliciesBecomeFlags(t *testing.T) {
	for name, test := range map[string]struct {
		change func(*domain.SigningIntent)
		want   []string
	}{
		"ASiC-S": {func(i *domain.SigningIntent) { i.Format = domain.FormatASiCS },
			[]string{"sign /tmp/contratto.pdf --format cades", "--asic s"}},
		"ASiC-E": {func(i *domain.SigningIntent) {
			i.Format, i.MoreDocuments = domain.FormatASiCE, []string{"/tmp/anexo.xml", "/tmp/plano.dwg"}
		}, []string{"sign /tmp/contratto.pdf /tmp/anexo.xml /tmp/plano.dwg --format xades", "--asic e"}},
		"FacturaE": {func(i *domain.SigningIntent) {
			i.DocumentPath, i.Format, i.Policy, i.Role = "/tmp/factura.xml", domain.FormatFacturaE, domain.PolicyFacturaE30, "receptor"
		}, []string{"sign /tmp/factura.xml --format xades", "--policy facturae30", "--role receptor"}},
		"PAdES with AGE": {func(i *domain.SigningIntent) { i.Policy = domain.PolicyAGE },
			[]string{"--format pades", "--policy age"}},
	} {
		binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")
		intent := fullIntent()
		test.change(&intent)
		if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		line := strings.Join(recordedArguments(t, recorded), " ")
		for _, wanted := range test.want {
			if !strings.Contains(line, wanted) {
				t.Errorf("%s: %q lacks %q", name, line, wanted)
			}
		}
	}
}

// TestThePDFPasswordTravelsInTheEnvironment, never on the command line.
func TestThePDFPasswordTravelsInTheEnvironment(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "environment")
	binary, recorded := fakeCommand(t, "printf '%s' \"$TREBARUNA_PDF_PASSWORD\" > "+seen+"; echo '"+receiptJSON+"'")
	intent := fullIntent()
	intent.PDFPassword = "abierto"
	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(seen); string(got) != "abierto" {
		t.Errorf("environment carried %q", got)
	}
	if contains(recordedArguments(t, recorded), "abierto") {
		t.Error("the password reached the command line")
	}
}
