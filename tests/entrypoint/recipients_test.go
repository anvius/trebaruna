package cli_test

// The recipients' address book through the command line: a certificate
// saved once is encrypted for by name, openssl opens the envelope with the
// recipient's key, and the book stays the user's alone.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
)

func TestASavedRecipientIsEncryptedForByName(t *testing.T) {
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	directory := t.TempDir()
	certificate, key, _ := opensslRecipient(t, directory, "LUCA BIANCHI", "x")

	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"recipients", "add", certificate, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("add: %d %s", code, stderr.String())
	}
	var saved map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &saved); err != nil || saved["holder"] != "LUCA BIANCHI" {
		t.Fatalf("saved %v, %v", saved, err)
	}
	book := filepath.Join(config, "trebaruna", "recipients")
	if info, err := os.Stat(book); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the book is the user's alone: %v %v", info, err)
	}
	if info, err := os.Stat(saved["path"].(string)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("each certificate file too: %v %v", info, err)
	}

	stdout.Reset()
	if code := cli.Run([]string{"recipients", "list"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "LUCA BIANCHI") {
		t.Errorf("list: %d %q", code, stdout.String())
	}

	document := filepath.Join(directory, "nota.txt")
	os.WriteFile(document, []byte("riservato\n"), 0o600)
	stdout.Reset()
	if code := cli.Run([]string{"encrypt", document, "--to", "saved:bianchi"}, &stdout, &stderr); code != 0 {
		t.Fatalf("encrypt for a saved recipient: %d %s", code, stderr.String())
	}
	opened, err := exec.Command("openssl", "cms", "-decrypt", "-inform", "DER", "-in", document+".p7e",
		"-recip", certificate, "-inkey", key).Output()
	if err != nil || string(opened) != "riservato\n" {
		t.Errorf("openssl opens the envelope with the saved recipient's key: %v %q", err, opened)
	}

	stderr.Reset()
	if code := cli.Run([]string{"encrypt", document, "--to", "saved:rossi", "--out", document + ".2.p7e"}, &stdout, &stderr); code == 0 ||
		!strings.Contains(stderr.String(), "no saved recipient matches") {
		t.Errorf("an unknown name: %d %s", code, stderr.String())
	}

	stdout.Reset()
	if code := cli.Run([]string{"recipients", "remove", saved["fingerprint"].(string)[:8]}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "removed") {
		t.Errorf("remove by fingerprint start: %d %s", code, stderr.String())
	}
	stdout.Reset()
	cli.Run([]string{"recipients", "list"}, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "no saved recipients") {
		t.Errorf("after removing: %q", stdout.String())
	}
}
