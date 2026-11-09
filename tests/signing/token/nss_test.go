package infrastructure_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// nssDirectory makes a directory that looks like an NSS store.
func nssDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cert9.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTheFirefoxProfileFirefoxStartsWithComesFirst: a person with several
// profiles means the one Firefox opens, then the one marked default.
func TestTheFirefoxProfileFirefoxStartsWithComesFirst(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".mozilla", "firefox")
	for _, profile := range []string{"aaaa.old", "bbbb.default", "cccc.default-release", "dddd.empty"} {
		nssDirectory(t, filepath.Join(root, profile))
	}
	if err := os.Remove(filepath.Join(root, "dddd.empty", "cert9.db")); err != nil {
		t.Fatal(err)
	}
	ini := "[Profile1]\nName=old\nIsRelative=1\nPath=aaaa.old\n\n" +
		"[Profile0]\nName=default\nIsRelative=1\nPath=bbbb.default\nDefault=1\n\n" +
		"[Profile2]\nName=empty\nIsRelative=1\nPath=dddd.empty\n\n" +
		"[Install4F96D1932A9F858E]\nDefault=cccc.default-release\nLocked=1\n\n" +
		"[General]\nStartWithLastProfile=1\nVersion=2\n"
	if err := os.WriteFile(filepath.Join(root, "profiles.ini"), []byte(ini), 0o600); err != nil {
		t.Fatal(err)
	}
	nssDirectory(t, filepath.Join(home, ".pki", "nssdb"))

	stores := infrastructure.NSSStores(home, "linux")
	var directories []string
	for _, store := range stores {
		directories = append(directories, strings.TrimPrefix(store.Directory, home))
	}
	want := []string{
		"/.mozilla/firefox/cccc.default-release",
		"/.mozilla/firefox/bbbb.default",
		"/.mozilla/firefox/aaaa.old",
		"/.pki/nssdb",
	}
	if !slices.Equal(directories, want) {
		t.Errorf("stores %v, want %v (a profile without a database is not a store)", directories, want)
	}
	if stores[0].Name != "Firefox (cccc.default-release)" {
		t.Errorf("name %q", stores[0].Name)
	}
}

// TestASnapOrFlatpakFirefoxIsFound: the sandboxed packages keep the profiles
// elsewhere.
func TestASnapOrFlatpakFirefoxIsFound(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox")
	nssDirectory(t, filepath.Join(root, "zzzz.default"))
	ini := "[Profile0]\nIsRelative=1\nPath=zzzz.default\nDefault=1\n"
	if err := os.WriteFile(filepath.Join(root, "profiles.ini"), []byte(ini), 0o600); err != nil {
		t.Fatal(err)
	}
	stores := infrastructure.NSSStores(home, "linux")
	if len(stores) != 1 || !strings.HasSuffix(stores[0].Directory, "zzzz.default") {
		t.Errorf("stores %+v", stores)
	}
}

// TestTheStoreOpensReadOnly: the browser's database is never written.
func TestTheStoreOpensReadOnly(t *testing.T) {
	parameters := infrastructure.SoftwareStore{Directory: "/home/maria/.mozilla/firefox/x.default"}.Parameters()
	if !strings.Contains(parameters, "configdir='sql:/home/maria/.mozilla/firefox/x.default'") ||
		!strings.Contains(parameters, "flags=readOnly") {
		t.Errorf("parameters %q", parameters)
	}
	quoted := infrastructure.SoftwareStore{Directory: "/home/o'brien/nss"}.Parameters()
	if !strings.Contains(quoted, `configdir="sql:/home/o'brien/nss"`) {
		t.Errorf("a quote in the path must not end the value: %q", quoted)
	}
}

// TestNSSIsLookedForWhereEachSystemInstallsIt.
func TestNSSIsLookedForWhereEachSystemInstallsIt(t *testing.T) {
	cases := []struct{ system, architecture, expected string }{
		{"linux", "amd64", "/usr/lib/x86_64-linux-gnu/libsoftokn3.so"},
		{"linux", "arm64", "/usr/lib/aarch64-linux-gnu/libsoftokn3.so"},
		{"linux", "amd64", "/usr/lib64/libsoftokn3.so"},
		{"darwin", "arm64", "/Applications/Firefox.app/Contents/MacOS/libsoftokn3.dylib"},
		{"windows", "amd64", `C:\Program Files\Mozilla Firefox\softokn3.dll`},
	}
	for _, entry := range cases {
		if !slices.Contains(infrastructure.NSSLocations(entry.system, entry.architecture), entry.expected) {
			t.Errorf("%s/%s: %s is not tried", entry.system, entry.architecture, entry.expected)
		}
	}
}
