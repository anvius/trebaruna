package cli_test

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnAfirmaRequestIsShownAndDeclinedWithoutApproval.
func TestAnAfirmaRequestIsShownAndDeclinedWithoutApproval(t *testing.T) {
	stdout, stderr, code := run("afirma", "afirma://sign?format=CAdES&algorithm=SHA256&appname=SEDE&dat=aG9sYQ%3D%3D")
	if code != 0 || strings.TrimSpace(stdout) != "CANCEL" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	for _, shown := range []string{"operation  sign", "format     CAdES", "4 bytes", "SEDE", "not approved"} {
		if !strings.Contains(stderr, shown) {
			t.Errorf("the request must show %q:\n%s", shown, stderr)
		}
	}
}

// TestAnApprovedAfirmaRequestPrintsTheAnswer: without a channel the answer is
// printed, cert|signature, and OpenSSL verifies the signature.
func TestAnApprovedAfirmaRequestPrintsTheAnswer(t *testing.T) {
	key := writeIdentityP12(t, "segreto", "MARIA GARCIA", 31)
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	stdout, stderr, code := run("afirma", "afirma://sign?format=CAdES&algorithm=SHA256&dat=aG9sYQ%3D%3D", "--approve", "--p12", key)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	parts := strings.Split(strings.TrimSpace(stdout), "|")
	if len(parts) != 2 {
		t.Fatalf("answer %q", stdout)
	}
	signature, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	path := filepath.Join(t.TempDir(), "firma.p7m")
	os.WriteFile(path, signature, 0o600)
	if output, err := exec.Command("openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", path, "-out", os.DevNull).CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v\n%s", err, output)
	}
}

// TestAnInvalidAfirmaRequestIsExplained.
func TestAnInvalidAfirmaRequestIsExplained(t *testing.T) {
	stdout, _, code := run("afirma", "afirma://sign?format=OOXML&algorithm=SHA256")
	if code == 0 || !strings.HasPrefix(stdout, "SAF_06") {
		t.Errorf("exit %d, stdout %q", code, stdout)
	}
}
