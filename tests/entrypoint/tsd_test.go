package cli_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/tsd"
	"codeberg.org/simplicer/trebaruna/tests/support/tsa"
)

type tsdReport struct {
	FileName string `json:"file_name"`
	Matches  bool   `json:"matches"`
	Tokens   []struct {
		Matches bool   `json:"matches"`
		Renews  bool   `json:"renews"`
		TSA     string `json:"tsa"`
	} `json:"tokens"`
}

func verifyTSD(t *testing.T, path string) (tsdReport, int) {
	t.Helper()
	stdout, stderr, code := run("verify-tsr", path, "--json")
	var report tsdReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("verify-tsr printed %q (stderr %q)", stdout, stderr)
	}
	return report, code
}

// TestADocumentKeepsItsTimestampInOneFile: the .tsd carries the document and
// the token, and OpenSSL accepts the token for the document inside.
func TestADocumentKeepsItsTimestampInOneFile(t *testing.T) {
	authority := tsa.New(t)
	document := writeDocument(t, "verbale.pdf", "%PDF-1.4 verbale di assemblea\n")
	if _, stderr, code := run("timestamp", document, "--tsa", authority.URL(t), "--tsd"); code != 0 {
		t.Fatalf("timestamp --tsd: %s", stderr)
	}

	report, code := verifyTSD(t, document+".tsd")
	if code != 0 || !report.Matches || report.FileName != "verbale.pdf" || len(report.Tokens) != 1 || report.Tokens[0].TSA != "Test TSA" {
		t.Fatalf("exit %d, report %+v", code, report)
	}

	// The independent judge: OpenSSL checks the token against the document.
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	raw, _ := os.ReadFile(document + ".tsd")
	decoded, err := tsd.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(document)
	if !bytes.Equal(decoded.Content, original) {
		t.Fatal("the .tsd must carry the document unchanged")
	}
	directory := t.TempDir()
	token, ca := filepath.Join(directory, "token.der"), filepath.Join(directory, "ca.pem")
	os.WriteFile(token, decoded.Tokens[0], 0o600)
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.CA.Raw}), 0o600)
	verify := exec.Command("openssl", "ts", "-verify", "-in", token, "-token_in", "-data", document, "-CAfile", ca)
	if output, err := verify.CombinedOutput(); err != nil || !strings.Contains(string(output), "Verification: OK") {
		t.Fatalf("openssl ts -verify: %v\n%s", err, output)
	}
}

// TestAnAlteredTSDIsCaught: one changed byte of the document breaks the imprint.
func TestAnAlteredTSDIsCaught(t *testing.T) {
	authority := tsa.New(t)
	document := writeDocument(t, "delibera.txt", "La delibera approvata il 9 novembre\n")
	if _, stderr, code := run("timestamp", document, "--tsa", authority.URL(t), "--tsd"); code != 0 {
		t.Fatalf("timestamp --tsd: %s", stderr)
	}
	raw, _ := os.ReadFile(document + ".tsd")
	altered := bytes.Replace(raw, []byte("9 novembre"), []byte("8 novembre"), 1)
	os.WriteFile(document+".tsd", altered, 0o600)

	report, code := verifyTSD(t, document+".tsd")
	if report.Matches || code == 0 {
		t.Errorf("an altered document must not match (exit %d, %+v)", code, report)
	}
}

// TestTheDocumentComesOutOfANestedTSD: name.pdf.p7m.tsd, as Italian offices
// keep them, gives back name.pdf.
func TestTheDocumentComesOutOfANestedTSD(t *testing.T) {
	authority := tsa.New(t)
	document := writeDocument(t, "contratto.pdf", "%PDF-1.4 contratto\n")
	key := writeIdentityP12(t, "segreto", "MARIO ROSSI", 7)
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	if _, stderr, code := run("sign", document, "--p12", key, "--format", "cades"); code != 0 {
		t.Fatalf("sign: %s", stderr)
	}
	if _, stderr, code := run("timestamp", document+".p7m", "--tsa", authority.URL(t), "--tsd"); code != 0 {
		t.Fatalf("timestamp --tsd: %s", stderr)
	}
	original, _ := os.ReadFile(document)
	os.Remove(document)

	if _, stderr, code := run("extract", document+".p7m.tsd"); code != 0 {
		t.Fatalf("extract: %s", stderr)
	}
	extracted, err := os.ReadFile(document)
	if err != nil || !bytes.Equal(extracted, original) {
		t.Fatalf("the document must come out byte for byte: %v", err)
	}
}

// TestARenewalTimestampIsChecked: a later token covers the earlier one (RFC
// 5544, section 4.2), and is checked as such.
func TestARenewalTimestampIsChecked(t *testing.T) {
	authority := tsa.New(t)
	document := writeDocument(t, "archivio.txt", "Documento conservato\n")
	if _, stderr, code := run("timestamp", document, "--tsa", authority.URL(t), "--tsd"); code != 0 {
		t.Fatalf("timestamp --tsd: %s", stderr)
	}
	raw, _ := os.ReadFile(document + ".tsd")
	first, err := tsd.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}

	renewed := withRenewal(t, authority, raw, first.Evidence[0])
	os.WriteFile(document+".tsd", renewed, 0o600)
	report, code := verifyTSD(t, document+".tsd")
	if code != 0 || len(report.Tokens) != 2 || !report.Tokens[1].Renews || !report.Tokens[1].Matches {
		t.Fatalf("exit %d, report %+v", code, report)
	}

	// A renewal over something else is not a renewal of this file.
	wrong := withRenewal(t, authority, raw, []byte("not the previous token"))
	os.WriteFile(document+".tsd", wrong, 0o600)
	if report, code := verifyTSD(t, document+".tsd"); code == 0 || report.Tokens[1].Matches {
		t.Errorf("a renewal over other bytes must not match (exit %d, %+v)", code, report)
	}
}

// withRenewal appends a TimeStampAndCRL whose token covers covered.
func withRenewal(t *testing.T, authority *tsa.Authority, original, covered []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(covered)
	response, err := authority.Token(context.Background(), sum[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := tsd.TokenOf(response)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := tsd.Renew(original, token)
	if err != nil {
		t.Fatal(err)
	}
	return rebuilt
}

// TestATimestampSaysWhetherItsAuthorityIsQualified, offline, from the cached
// trusted list: unknown without one, "not qualified" for an authority the list
// does not grant (the test authority, checked against a real list when
// TREBARUNA_TSL_CACHE points at an XDG cache filled by `trust sync`).
func TestATimestampSaysWhetherItsAuthorityIsQualified(t *testing.T) {
	authority := tsa.New(t)
	t.Setenv("LC_ALL", "it_IT.UTF-8")
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	document := writeDocument(t, "atto.txt", "atto\n")

	stdout, stderr, code := run("timestamp", document, "--tsa", authority.URL(t), "--json")
	if code != 0 || !strings.Contains(stdout, `"qualified": false`) || !strings.Contains(stdout, "not cached") {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}

	cache := os.Getenv("TREBARUNA_TSL_CACHE")
	if cache == "" {
		t.Skip("set TREBARUNA_TSL_CACHE to an XDG cache holding the IT list to check against it")
	}
	t.Setenv("XDG_CACHE_HOME", cache)
	os.Remove(document + ".tsr")
	stdout, _, _ = run("timestamp", document, "--tsa", authority.URL(t), "--json")
	if !strings.Contains(stdout, `"qualified": false`) || !strings.Contains(stdout, "grants no such service") {
		t.Errorf("the test authority is not qualified by the IT list: %s", stdout)
	}
}
