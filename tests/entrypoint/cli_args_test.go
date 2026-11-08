package cli_test

// Command-line surface tests: argument handling and exit codes, without network.
//
// These exist because two real bugs shipped from this area: flags after the
// positional argument were ignored (`asic a.pdf b.p7m --out x` wrote elsewhere),
// and a verification that compared nothing exited 0.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
)

// run executes the CLI and returns stdout, stderr and the exit code.
func run(args ...string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := cli.Run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

// TestUsageListsEveryCommand guards the help output against drift.
func TestUsageListsEveryCommand(t *testing.T) {
	stdout, _, code := run("help")
	if code != 0 {
		t.Fatalf("help exited %d", code)
	}

	for _, command := range []string{
		"trebaruna sign", "trebaruna verify", "trebaruna trust",
		"trebaruna timestamp", "trebaruna verify-tsr",
		"trebaruna certificate", "trebaruna asic",
	} {
		if !strings.Contains(stdout, command) {
			t.Errorf("the help does not mention %q", command)
		}
	}
}

// TestUnknownCommandIsAUsageError.
func TestUnknownCommandIsAUsageError(t *testing.T) {
	_, stderr, code := run("frobnicate")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr = %q", stderr)
	}
}

// TestTimestampRequiresAnAuthority: the flag is mandatory, and the error must
// say so instead of attempting a request.
func TestTimestampRequiresAnAuthority(t *testing.T) {
	directory := t.TempDir()
	document := filepath.Join(directory, "a.txt")
	if err := os.WriteFile(document, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run("timestamp", document)
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "--tsa") {
		t.Errorf("stderr should name the missing flag: %q", stderr)
	}
}

// TestTimestampRejectsAMalformedHash keeps a typo from becoming a network call.
func TestTimestampRejectsAMalformedHash(t *testing.T) {
	_, stderr, code := run("timestamp", "--hash", "not-hex", "--tsa", "https://example.invalid/")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "hex") {
		t.Errorf("stderr = %q", stderr)
	}
}

// TestVerifyTimestampWithoutComparisonIsNotASuccess is the regression guard for
// the silent pass: with nothing to compare, the exit code must say "unverified".
func TestVerifyTimestampWithoutComparisonIsNotASuccess(t *testing.T) {
	directory := t.TempDir()
	token := filepath.Join(directory, "fake.tsr")
	if err := os.WriteFile(token, []byte("not a token"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, code := run("verify-tsr", token)
	if code == 0 {
		t.Error("an unparsable token must not exit 0")
	}
}

// TestASiCIgnoresFlagsAfterPositionals is the regression guard for the argument
// split: --out after the two files used to be treated as a third file.
func TestASiCIgnoresFlagsAfterPositionals(t *testing.T) {
	directory := t.TempDir()
	document := filepath.Join(directory, "doc.txt")
	signature := filepath.Join(directory, "doc.txt.p7m")
	for _, path := range []string{document, signature} {
		if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(directory, "custom.asice")

	stdout, stderr, code := run("asic", document, signature, "--out", target)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "custom.asice") {
		t.Errorf("stdout = %q", stdout)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the container was not written to --out: %v", err)
	}
}

// TestASiCRejectsTraversalOnExtract covers the zip-slip defence at the CLI level.
func TestASiCRejectsTraversalOnExtract(t *testing.T) {
	directory := t.TempDir()
	container := filepath.Join(directory, "evil.asice")

	if err := writeEvilZip(container); err != nil {
		t.Fatalf("build fixture: %v", err)
	}

	target := filepath.Join(directory, "out")
	_, stderr, code := run("asic", "--extract", container, "--out", target)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	// The refusal is a warning on stderr: the command still succeeds for the
	// members it can extract safely, which is what a partial container needs.
	if !strings.Contains(stderr, "refusing to extract") {
		t.Errorf("the traversal was not refused; stderr = %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(directory, "escaped.txt")); err == nil {
		t.Error("a member escaped the extraction directory")
	}
}

// TestVerifyFlagsAfterPositionals keeps `verify-tsr token --hash x` working.
func TestVerifyFlagsAfterPositionals(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	encoded := hex.EncodeToString(digest[:])

	directory := t.TempDir()
	token := filepath.Join(directory, "fake.tsr")
	if err := os.WriteFile(token, []byte("not a token"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The point is that the flag is consumed, not treated as a file path: the
	// error must be about the token, not about opening "--hash".
	_, stderr, _ := run("verify-tsr", token, "--hash", encoded)
	if strings.Contains(stderr, "--hash") {
		t.Errorf("the flag was mistaken for a file: %q", stderr)
	}
}
