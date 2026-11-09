package cli_test

import (
	"strings"
	"testing"
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
