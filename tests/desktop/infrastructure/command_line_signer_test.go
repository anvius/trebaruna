package infrastructure_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"
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
		KeyPath:      "/tmp/mario.p12",
		Passphrase:   "secret",
		Format:       "pades",
		Level:        "t",
		Page:         2,
		Box:          "100,600,300,700",
		TimestampURL: "https://tsa.example/tsa",
		Reason:       "Contratto",
		Location:     "Roma",
	}
}

const receiptJSON = `{"path":"/tmp/contratto_signed.pdf","standard":"PAdES-B-T","signer":"MARIO ROSSI",` +
	`"signed_at":"2026-11-09T10:00:00+01:00","seal_count":1,"self_signed":true}`

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
		"--box":      "100,600,300,700",
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
	intent.KeyPath = "/tmp/mario.PEM"

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
	intent := domain.SigningIntent{DocumentPath: "/tmp/a.pdf", KeyPath: "/tmp/k.p12", Format: "pades", Level: "bes", Page: 1}

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, flag := range []string{"--page", "--box", "--tsa", "--reason", "--location", "--pass"} {
		if contains(recordedArguments(t, recorded), flag) {
			t.Errorf("%s must not be sent when the intent leaves it empty", flag)
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
	}
	if receipt != want {
		t.Errorf("receipt = %+v, want %+v", receipt, want)
	}
}

func TestAFailureCarriesTheCommandsExplanation(t *testing.T) {
	binary, _ := fakeCommand(t, "echo 'signing failed: pkcs12: decryption password incorrect' >&2; exit 4")

	_, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), fullIntent())
	if err == nil || !strings.Contains(err.Error(), "decryption password incorrect") {
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
