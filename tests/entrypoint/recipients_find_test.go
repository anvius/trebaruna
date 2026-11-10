package cli_test

// `recipients find` looks a person up in an LDAP directory, says of each
// certificate whether it can receive envelopes, keeps the fit ones with
// --save, and an envelope is then made for the one found.

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/tests/support/ldapserver"
)

func TestARecipientFoundInADirectoryIsKeptAndEncryptedFor(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	directory := t.TempDir()
	certificate, key, _ := opensslRecipient(t, directory, "MARIA LOPEZ", "x")
	signingOnly := filepath.Join(directory, "firma.pem")
	if output, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", filepath.Join(directory, "firma.key"),
		"-out", signingOnly, "-days", "2", "-subj", "/CN=MARIA LOPEZ firma", "-addext", "keyUsage=critical,digitalSignature").CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v\n%s", err, output)
	}
	der := func(path string) []byte {
		content, _ := os.ReadFile(path)
		block, _ := pem.Decode(content)
		return block.Bytes
	}
	server := ldapserver.Start(t, nil, ldapserver.Entry{DN: "cn=Maria Lopez,o=Example,c=ES", Mail: "maria@example.org",
		Certificates: [][]byte{der(certificate), der(signingOnly)}})
	url := "ldap://" + server.Address + "/o=Example,c=ES"

	stdout, stderr, code := run("recipients", "find", "maria@example.org", "--ldap", url)
	if code != 0 || !strings.Contains(stdout, "MARIA LOPEZ (MARIA LOPEZ), until") || !strings.Contains(stdout, "can receive envelopes") ||
		!strings.Contains(stdout, "for signing only") || !strings.Contains(stdout, "directory    ldap ldap://"+server.Address+"/") {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}

	stdout, stderr, code = run("recipients", "find", "maria@example.org", "--ldap", url, "--save", "--json")
	var report struct {
		Certificates []struct {
			Holder string
			Usable bool
			Saved  bool
		}
		Connections []struct{ Purpose string }
	}
	if code != 0 || json.Unmarshal([]byte(stdout), &report) != nil || len(report.Certificates) != 2 ||
		!report.Certificates[0].Saved || report.Certificates[1].Saved || report.Certificates[1].Usable ||
		len(report.Connections) != 1 || report.Connections[0].Purpose != "directory" {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}

	document := filepath.Join(directory, "nota.txt")
	os.WriteFile(document, []byte("reservado\n"), 0o600)
	if _, stderr, code := run("encrypt", document, "--to", "saved:maria"); code != 0 {
		t.Fatalf("encrypt for the recipient found: %d %s", code, stderr)
	}
	opened, err := exec.Command("openssl", "cms", "-decrypt", "-inform", "DER", "-in", document+".p7e", "-recip", certificate, "-inkey", key).Output()
	if err != nil || string(opened) != "reservado\n" {
		t.Errorf("openssl opens the envelope: %v %q", err, opened)
	}

	if _, stderr, code := run("recipients", "find", "maria@example.org"); code != 2 || !strings.Contains(stderr, "--ldap") {
		t.Errorf("without a directory: %d %s", code, stderr)
	}
}
