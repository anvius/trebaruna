package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheLocalChannelCertificateIsInstalledAndRemovedOnRequest.
func TestTheLocalChannelCertificateIsInstalledAndRemovedOnRequest(t *testing.T) {
	if _, err := exec.LookPath("certutil"); err != nil {
		t.Skip("certutil is not installed")
	}
	database, directory := t.TempDir(), filepath.Join(t.TempDir(), "localtls")
	if output, err := exec.Command("certutil", "-N", "-d", "sql:"+database, "--empty-password").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, output)
	}
	if stdout, _, _ := run("afirma", "local-tls", "status", "--dir", directory, "--nss-db", database); !strings.Contains(stdout, "no certificate made yet") ||
		!strings.Contains(stdout, "not installed") {
		t.Errorf("status before: %s", stdout)
	}
	stdout, stderr, code := run("afirma", "local-tls", "install", "--dir", directory, "--nss-db", database)
	if code != 0 || !strings.Contains(stdout, "key was destroyed") || !strings.Contains(stdout, database) {
		t.Fatalf("install: exit %d, %s %s", code, stdout, stderr)
	}
	if stdout, _, _ := run("afirma", "local-tls", "status", "--dir", directory, "--nss-db", database); !strings.Contains(stdout, ": installed") {
		t.Errorf("status after: %s", stdout)
	}
	if _, stderr, code := run("afirma", "local-tls", "remove", "--dir", directory, "--nss-db", database); code != 0 {
		t.Fatalf("remove: %s", stderr)
	}
	if _, err := os.Stat(directory); err == nil {
		t.Error("the certificate stayed on disk")
	}
	if stdout, _, _ := run("afirma", "local-tls", "status", "--dir", directory, "--nss-db", database); !strings.Contains(stdout, "not installed") {
		t.Errorf("status after removing: %s", stdout)
	}
}
