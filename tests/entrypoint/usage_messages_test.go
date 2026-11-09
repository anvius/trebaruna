package cli_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
)

// TestEachCommandNamesItselfWhenItLacksADocument: verify, extract and
// certificate said "sign needs a document path".
func TestEachCommandNamesItselfWhenItLacksADocument(t *testing.T) {
	for _, command := range []string{"verify", "extract", "certificate"} {
		_, stderr, code := run(command)
		if code == 0 || !strings.Contains(stderr, command+" needs a document path") || strings.Contains(stderr, "sign needs") {
			t.Errorf("%s: exit %d, %q", command, code, stderr)
		}
	}
}

// TestAMissingPassphraseSaysWhereItGoes: without a passphrase the error
// says so and names the variable, instead of a placeholder name.
func TestAMissingPassphraseSaysWhereItGoes(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "")
	_, stderr, code := run("sign", writeOnePagePDF(t), "--p12", key)
	if code == 0 || !strings.Contains(stderr, "does not open without its passphrase") || !strings.Contains(stderr, "$TREBARUNA_PASSPHRASE") ||
		strings.Contains(stderr, "certificate holder") {
		t.Errorf("exit %d, %q", code, stderr)
	}
	t.Setenv("TREBARUNA_PASSPHRASE", "wrong")
	if _, stderr, _ := run("sign", writeOnePagePDF(t), "--p12", key); !strings.Contains(stderr, "the passphrase does not open the PKCS#12 file") {
		t.Errorf("a wrong passphrase: %q", stderr)
	}
}

// TestAFailureIsJSONWhenJSONWasAskedFor: whatever the command, a failure
// with --json leaves a JSON object on stdout, the reason and the exit
// code; a person's usage text stays out of it.
func TestAFailureIsJSONWhenJSONWasAskedFor(t *testing.T) {
	for _, arguments := range [][]string{
		{"sign", "/nonexistent.pdf", "--json"},
		{"verify", "/nonexistent.pdf", "--json"},
		{"certificate", "/nonexistent.p12", "--json"},
		{"encrypt", "x", "--json"},
		{"sign", "--json", "--nonsense"},
	} {
		var stdout, stderr bytes.Buffer
		code := cli.Run(arguments, &stdout, &stderr)
		var failure struct {
			Error    string `json:"error"`
			ExitCode int    `json:"exit_code"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &failure); err != nil || failure.Error == "" || failure.ExitCode != code || code == 0 {
			t.Errorf("%v: stdout %q, exit %d", arguments, stdout.String(), code)
		}
		if strings.Contains(failure.Error, "usage:") {
			t.Errorf("%v: the usage text reached the JSON", arguments)
		}
		if stderr.Len() == 0 {
			t.Errorf("%v: stderr keeps the message for a person", arguments)
		}
	}
	var stdout, stderr bytes.Buffer
	cli.Run([]string{"sign", "/nonexistent.pdf"}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("without --json nothing goes to stdout: %q", stdout.String())
	}
}
