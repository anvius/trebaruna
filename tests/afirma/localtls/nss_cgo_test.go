//go:build cgo

package localtls_test

// The root goes into an NSS store and comes out again, through softokn3 and
// with no NSS tool: certutil, where it is installed, is only a cross-check.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/localtls"
)

func TestTheRootGoesInAndOutOfAnNSSStore(t *testing.T) {
	if !localtls.Available() {
		t.Skip("softokn3 is not installed")
	}
	database := filepath.Join(t.TempDir(), "profile")
	if err := localtls.CreateStore(database); err != nil {
		t.Fatal(err)
	}
	material, err := localtls.Generate(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if presence, err := localtls.Check(database); err != nil || presence != localtls.Absent {
		t.Fatalf("before the install: %v, %v", presence, err)
	}

	if err := localtls.Install(material, []string{database}); err != nil {
		t.Fatal(err)
	}
	if presence, err := localtls.Check(database); err != nil || presence != localtls.Present {
		t.Fatalf("after the install: %v, %v", presence, err)
	}
	// Installing again replaces the root: it is not listed twice.
	if err := localtls.Install(material, []string{database}); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("certutil"); err == nil {
		listing, _ := exec.Command("certutil", "-L", "-d", "sql:"+database).CombinedOutput()
		count, trusted := 0, false
		for _, line := range strings.Split(string(listing), "\n") {
			if strings.Contains(line, localtls.Nickname) {
				count++
				trusted = strings.HasSuffix(strings.TrimSpace(line), "C,,")
			}
		}
		if count != 1 || !trusted {
			t.Errorf("certutil lists the root %d times, trusted as a server authority %v:\n%s", count, trusted, listing)
		}
	}

	if err := localtls.Remove([]string{database}); err != nil {
		t.Fatal(err)
	}
	if presence, err := localtls.Check(database); err != nil || presence != localtls.Absent {
		t.Errorf("after the removal: %v, %v", presence, err)
	}
}

// TestACertutilStoreShowsTheRoot: a root certutil installed, with no nickname on
// its trust object, is found and removed too.
func TestACertutilStoreShowsTheRoot(t *testing.T) {
	if _, err := exec.LookPath("certutil"); err != nil {
		t.Skip("certutil is not installed")
	}
	if !localtls.Available() {
		t.Skip("softokn3 is not installed")
	}
	database := t.TempDir()
	if output, err := exec.Command("certutil", "-N", "-d", "sql:"+database, "--empty-password").CombinedOutput(); err != nil {
		t.Fatalf("certutil -N: %v %s", err, output)
	}
	material, err := localtls.Generate(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pemFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(pemFile, material.RootPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("certutil", "-A", "-n", localtls.Nickname, "-t", "C,,", "-i", pemFile, "-d", "sql:"+database).CombinedOutput(); err != nil {
		t.Fatalf("certutil -A: %v %s", err, output)
	}
	if presence, err := localtls.Check(database); err != nil || presence != localtls.Present {
		t.Fatalf("the root certutil installed: %v, %v", presence, err)
	}
	if err := localtls.Remove([]string{database}); err != nil {
		t.Fatal(err)
	}
	if output, _ := exec.Command("certutil", "-L", "-d", "sql:"+database).CombinedOutput(); strings.Contains(string(output), localtls.Nickname) {
		t.Errorf("removal left the root in the store:\n%s", output)
	}
}
