package cli_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/tests/support/tsa"
)

type verifyResult struct {
	Verdict string `json:"verdict"`
	Signers []struct {
		Integrity string `json:"integrity"`
		Findings  []struct {
			Code string `json:"code"`
		} `json:"findings"`
	} `json:"signers"`
}

func writeDocument(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func verifyJSON(t *testing.T, arguments ...string) verifyResult {
	t.Helper()
	stdout, stderr, _ := run(append([]string{"verify"}, append(arguments, "--json")...)...)
	var result verifyResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("verify printed %q (stderr %q)", stdout, stderr)
	}
	if len(result.Signers) != 1 {
		t.Fatalf("signers = %d", len(result.Signers))
	}
	return result
}

func TestADetachedSignatureTravelsBesideItsDocument(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeDocument(t, "contratto.txt", "contratto di prova\n")

	stdout, stderr, code := run("sign", document, "--p12", key, "--format", "cades", "--detached", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, `"path": "`+document+`.p7s"`) {
		t.Fatalf("stdout = %s, want the .p7s beside the document", stdout)
	}
	signature := document + ".p7s"
	if raw, _ := os.ReadFile(signature); strings.Contains(string(raw), "contratto di prova") {
		t.Error("a detached signature must not carry the document")
	}

	// The document beside it is found without being named.
	if result := verifyJSON(t, signature); result.Signers[0].Integrity != "good" {
		t.Errorf("with the document beside it: integrity %s", result.Signers[0].Integrity)
	}
	// Another document is not the one signed.
	other := writeDocument(t, "altro.txt", "altro\n")
	if result := verifyJSON(t, signature, "--content", other); result.Verdict != "broken" {
		t.Errorf("with another document: verdict %s, want broken", result.Verdict)
	}
	// Without any document the bytes cannot be compared: unknown, not broken.
	if err := os.Remove(document); err != nil {
		t.Fatal(err)
	}
	if result := verifyJSON(t, signature); result.Signers[0].Integrity != "unknown" || result.Verdict == "broken" {
		t.Errorf("without the document: integrity %s, verdict %s", result.Signers[0].Integrity, result.Verdict)
	}
}

func TestOpenSSLVerifiesADetachedTimestampedSignature(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	authority := tsa.New(t)
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeDocument(t, "fattura.xml", "<fattura/>")

	if _, stderr, code := run("sign", document, "--p12", key, "--format", "cades", "--detached", "--level", "t", "--tsa", authority.URL(t)); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	verify := exec.Command("openssl", "cms", "-verify", "-inform", "DER", "-in", document+".p7s",
		"-content", document, "-noverify", "-binary", "-out", os.DevNull)
	if output, err := verify.CombinedOutput(); err != nil || !strings.Contains(string(output), "Verification successful") {
		t.Fatalf("openssl: %v\n%s", err, output)
	}
	if result := verifyJSON(t, document+".p7s"); result.Signers[0].Integrity != "good" {
		t.Errorf("integrity = %s", result.Signers[0].Integrity)
	}
}

func TestOnlyCAdESCanBeDetached(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	if _, _, code := run("sign", writeOnePagePDF(t), "--p12", key, "--detached"); code == 0 {
		t.Error("a PDF signature carries its signature inside; --detached must be refused")
	}
}
