package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/localtls"
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

// makeNSSStore creates an NSS store in a folder, as Firefox or Chromium do.
func makeNSSStore(t *testing.T, directory string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("certutil", "-N", "-d", "sql:"+directory, "--empty-password").CombinedOutput(); err != nil {
		t.Fatalf("certutil -N: %v %s", err, output)
	}
}

// useHome points the program at a fake home folder, so that the browsers'
// stores found are only the ones the test makes.
func useHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	return home
}

// TestTheRootGoesToEveryStoreFoundAndLeavesEachOnRemoval: the stores are found
// from the home folder, and removal reaches a store the browser has since
// dropped from its profiles.ini, because the install recorded it.
func TestTheRootGoesToEveryStoreFoundAndLeavesEachOnRemoval(t *testing.T) {
	if _, err := exec.LookPath("certutil"); err != nil {
		t.Skip("certutil is not installed")
	}
	home := useHome(t)
	chromium := filepath.Join(home, ".pki", "nssdb")
	librewolf := filepath.Join(home, ".config", "librewolf", "librewolf")
	profile := filepath.Join(librewolf, "abcd.default")
	makeNSSStore(t, chromium)
	makeNSSStore(t, profile)
	profiles := filepath.Join(librewolf, "profiles.ini")
	if err := os.MkdirAll(librewolf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profiles, []byte("[Profile0]\nIsRelative=1\nPath=abcd.default\nDefault=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "localtls")

	stdout, stderr, code := run("afirma", "local-tls", "install", "--dir", directory)
	if code != 0 {
		t.Fatalf("install: exit %d, %s %s", code, stdout, stderr)
	}
	if !localtls.Installed(chromium) || !localtls.Installed(profile) {
		t.Fatalf("the root is not in every store found: %s", stdout)
	}
	if stdout, _, _ := run("afirma", "local-tls", "status", "--dir", directory); !strings.Contains(stdout, "LibreWolf (abcd.default) at "+profile+": installed") ||
		!strings.Contains(stdout, "Chromium (shared NSS store) at "+chromium+": installed") {
		t.Errorf("status names the stores: %s", stdout)
	}

	if err := os.WriteFile(profiles, []byte("[General]\nVersion=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := run("afirma", "local-tls", "remove", "--dir", directory); code != 0 {
		t.Fatalf("remove: %s", stderr)
	}
	if localtls.Installed(chromium) || localtls.Installed(profile) {
		t.Error("the root stayed in a store it was installed in")
	}
}

// TestAnExplicitStoreOverridesTheStoresFound: --nss-db names the one store, and
// the browsers' stores found are left alone.
func TestAnExplicitStoreOverridesTheStoresFound(t *testing.T) {
	if _, err := exec.LookPath("certutil"); err != nil {
		t.Skip("certutil is not installed")
	}
	home := useHome(t)
	found := filepath.Join(home, ".pki", "nssdb")
	makeNSSStore(t, found)
	explicit := filepath.Join(t.TempDir(), "chosen")
	makeNSSStore(t, explicit)
	directory := filepath.Join(t.TempDir(), "localtls")

	if _, stderr, code := run("afirma", "local-tls", "install", "--dir", directory, "--nss-db", explicit); code != 0 {
		t.Fatalf("install: %s", stderr)
	}
	if !localtls.Installed(explicit) || localtls.Installed(found) {
		t.Error("--nss-db must name the only store the root goes into")
	}
	if _, stderr, code := run("afirma", "local-tls", "remove", "--dir", directory, "--nss-db", explicit); code != 0 {
		t.Fatalf("remove: %s", stderr)
	}
}
