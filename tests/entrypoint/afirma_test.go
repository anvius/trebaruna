package cli_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
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

// interactiveLines runs afirma --interactive with the decisions given and
// returns the JSON lines it printed.
func interactiveLines(t *testing.T, uri string, decisions ...string) []map[string]any {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cli.RunIO([]string{"afirma", uri, "--interactive"}, strings.NewReader(strings.Join(decisions, "\n")+"\n"), &stdout, &stderr)
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("not a JSON line: %q (stderr %s)", raw, stderr.String())
		}
		lines = append(lines, line)
	}
	return lines
}

// TestTheWindowsProtocolCarriesTheDecisionThroughStdin: the proposal goes
// out, the key and its passphrase come back through the pipe.
func TestTheWindowsProtocolCarriesTheDecisionThroughStdin(t *testing.T) {
	key := writeIdentityP12(t, "segreto", "MARIA GARCIA", 32)
	decision := `{"approved":true,"key":{"p12":"` + key + `"},"passphrase":"segreto"}`
	lines := interactiveLines(t, "afirma://sign?format=CAdES&algorithm=SHA256&appname=SEDE&dat=aG9sYQ%3D%3D", decision)
	if len(lines) != 2 || lines[0]["type"] != "proposal" || lines[1]["type"] != "outcome" {
		t.Fatalf("lines %v", lines)
	}
	if lines[0]["app_name"] != "SEDE" || lines[0]["data_size"] != float64(4) || lines[0]["format"] != "CAdES" {
		t.Errorf("proposal %v", lines[0])
	}
	if answer, _ := lines[1]["answer"].(string); strings.Count(answer, "|") != 1 || lines[1]["delivered"] != true {
		t.Errorf("outcome %v", lines[1])
	}
}

// TestTheWindowIsAskedAgainForACertificateThePageRefuses.
func TestTheWindowIsAskedAgainForACertificateThePageRefuses(t *testing.T) {
	key := writeIdentityP12(t, "segreto", "MARIA GARCIA", 33)
	decision := `{"approved":true,"key":{"p12":"` + key + `"},"passphrase":"segreto"}`
	properties := base64.StdEncoding.EncodeToString([]byte("filter=subject.contains:ROSSI"))
	lines := interactiveLines(t, "afirma://sign?format=CAdES&algorithm=SHA256&dat=aG9sYQ%3D%3D&properties="+properties,
		decision, decision, decision)
	if len(lines) != 4 || lines[1]["rejected"] == nil || !strings.HasPrefix(lines[3]["answer"].(string), "SAF_19") {
		t.Errorf("lines %v", lines)
	}
}

// TestAClosedWindowDeclines.
func TestAClosedWindowDeclines(t *testing.T) {
	lines := interactiveLines(t, "afirma://sign?format=CAdES&algorithm=SHA256&dat=aG9sYQ%3D%3D")
	if lines[len(lines)-1]["answer"] != "CANCEL" {
		t.Errorf("lines %v", lines)
	}
}
