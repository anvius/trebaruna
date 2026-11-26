package infrastructure_test

// The browsers' NSS stores found from fake home folders (ADR-0020): every
// test works in t.TempDir(), never in a real profile.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/browserstores/domain"
	browserstores "codeberg.org/simplicer/trebaruna/src/browserstores/infrastructure"
)

// makeStore makes a folder that holds an NSS store.
func makeStore(t *testing.T, directory string) {
	t.Helper()
	writeFile(t, filepath.Join(directory, "cert9.db"), "")
}

// writeFile writes a file, creating its folders.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// describe lists each store as browser|packaging|folder under home|default.
func describe(home string, stores []domain.Store) []string {
	var lines []string
	for _, store := range stores {
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%t", store.Browser, store.Packaging,
			strings.TrimPrefix(store.Directory, home), store.Default))
	}
	return lines
}

func expectStores(t *testing.T, home string, stores []domain.Store, want ...string) {
	t.Helper()
	if got := describe(home, stores); !slices.Equal(got, want) {
		t.Errorf("stores\n got %q\nwant %q", got, want)
	}
}

// TestTheLibreWolfProfileOfTheXDGFolderIsFound is the case this module was
// written for: LibreWolf's profile under ~/.config, named by installs.ini.
func TestTheLibreWolfProfileOfTheXDGFolderIsFound(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".config", "librewolf", "librewolf")
	writeFile(t, filepath.Join(root, "profiles.ini"),
		"[Profile1]\nName=default\nIsRelative=1\nPath=6toeo0ct.default\n\n"+
			"[Profile0]\nName=default-default\nIsRelative=1\nPath=a1b2c3d4.default-default\nStoreID=0f0f0f0f\nDefault=1\n\n"+
			"[General]\nStartWithLastProfile=1\nVersion=2\n")
	writeFile(t, filepath.Join(root, "installs.ini"), "[0123456789ABCDEF]\nDefault=a1b2c3d4.default-default\nLocked=1\n")
	makeStore(t, filepath.Join(root, "a1b2c3d4.default-default"))
	makeStore(t, filepath.Join(root, "6toeo0ct.default"))
	makeStore(t, filepath.Join(home, ".pki", "nssdb"))

	found := browserstores.Discover(browserstores.NewEnvironment(home, "linux"))
	expectStores(t, home, found.Stores,
		"LibreWolf||/.config/librewolf/librewolf/a1b2c3d4.default-default|true",
		"LibreWolf||/.config/librewolf/librewolf/6toeo0ct.default|false",
		"Chromium||/.pki/nssdb|false",
	)
	if name := found.Stores[0].Name(); name != "LibreWolf (a1b2c3d4.default-default)" {
		t.Errorf("name %q", name)
	}
	if found.Stores[2].Name() != "Chromium (shared NSS store)" {
		t.Errorf("name %q", found.Stores[2].Name())
	}
}

// TestTheInstallsIniDefaultWinsOverDefaultOne: the profile an installation names
// opens first, even when another profile is marked Default=1.
func TestTheInstallsIniDefaultWinsOverDefaultOne(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".mozilla", "firefox")
	writeFile(t, filepath.Join(root, "profiles.ini"),
		"[Profile0]\nIsRelative=1\nPath=aaaa.first\nDefault=1\n\n[Profile1]\nIsRelative=1\nPath=bbbb.second\n")
	writeFile(t, filepath.Join(root, "installs.ini"), "[ABCDEF]\nDefault=bbbb.second\n")
	makeStore(t, filepath.Join(root, "aaaa.first"))
	makeStore(t, filepath.Join(root, "bbbb.second"))

	found := browserstores.Discover(browserstores.NewEnvironment(home, "linux"))
	expectStores(t, home, found.Stores,
		"Firefox||/.mozilla/firefox/bbbb.second|true",
		"Firefox||/.mozilla/firefox/aaaa.first|true",
	)
}

// TestAnAbsoluteProfileIsFoundWhereItIs: IsRelative=0 names a folder outside
// the profiles' folder; a relative profile without a store is not listed.
func TestAnAbsoluteProfileIsFoundWhereItIs(t *testing.T) {
	home := t.TempDir()
	elsewhere := filepath.Join(home, "disk", "perfil.x")
	root := filepath.Join(home, ".zen")
	writeFile(t, filepath.Join(root, "profiles.ini"),
		"[Profile0]\nIsRelative=0\nPath="+elsewhere+"\nDefault=1\n\n[Profile1]\nIsRelative=1\nPath=empty.default\n")
	makeStore(t, elsewhere)
	writeFile(t, filepath.Join(root, "empty.default", "prefs.js"), "")

	found := browserstores.Discover(browserstores.NewEnvironment(home, "linux"))
	expectStores(t, home, found.Stores, "Zen||"+strings.TrimPrefix(elsewhere, home)+"|true")
	if len(found.Skipped) != 0 {
		t.Errorf("skipped %v, want none: a folder without a database is not a store", found.Skipped)
	}
}

// TestSandboxedBrowsersAreFound: Snap and Flatpak keep their profiles in their
// own folders, and the Chromium stores of each package are listed.
func TestSandboxedBrowsersAreFound(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox", "profiles.ini"),
		"[Profile0]\nIsRelative=1\nPath=zzzz.default\nDefault=1\n")
	makeStore(t, filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox", "zzzz.default"))
	makeStore(t, filepath.Join(home, "snap", "chromium", "current", ".pki", "nssdb"))
	sandbox := filepath.Join(home, ".var", "app", "io.gitlab.librewolf-community")
	writeFile(t, filepath.Join(sandbox, "config", "librewolf", "librewolf", "profiles.ini"),
		"[Profile0]\nIsRelative=1\nPath=lw.default\nDefault=1\n")
	makeStore(t, filepath.Join(sandbox, "config", "librewolf", "librewolf", "lw.default"))
	makeStore(t, filepath.Join(home, ".var", "app", "org.chromium.Chromium", ".pki", "nssdb"))
	makeStore(t, filepath.Join(home, ".var", "app", "io.github.ungoogled_software.ungoogled_chromium", ".pki", "nssdb"))

	found := browserstores.Discover(browserstores.NewEnvironment(home, "linux"))
	expectStores(t, home,
		found.Stores,
		"Firefox|snap|/snap/firefox/common/.mozilla/firefox/zzzz.default|true",
		"Chromium|snap|/snap/chromium/current/.pki/nssdb|false",
		"LibreWolf|flatpak io.gitlab.librewolf-community|/.var/app/io.gitlab.librewolf-community/config/librewolf/librewolf/lw.default|true",
		"Chromium|flatpak org.chromium.Chromium|/.var/app/org.chromium.Chromium/.pki/nssdb|false",
		"ungoogled-chromium|flatpak io.github.ungoogled_software.ungoogled_chromium|/.var/app/io.github.ungoogled_software.ungoogled_chromium/.pki/nssdb|false",
	)
}

// TestAFolderWithOnlyALegacyStoreIsSkippedAndSaidSo: cert8.db is not read, and
// the folder is reported; a profile with no database at all is not reported.
func TestAFolderWithOnlyALegacyStoreIsSkippedAndSaidSo(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".mozilla", "firefox")
	writeFile(t, filepath.Join(root, "profiles.ini"),
		"[Profile0]\nIsRelative=1\nPath=old.default\nDefault=1\n\n[Profile1]\nIsRelative=1\nPath=empty.default\n")
	writeFile(t, filepath.Join(root, "old.default", "cert8.db"), "")
	writeFile(t, filepath.Join(root, "empty.default", "prefs.js"), "")

	found := browserstores.Discover(browserstores.NewEnvironment(home, "linux"))
	if len(found.Stores) != 0 {
		t.Errorf("stores %v, want none", describe(home, found.Stores))
	}
	if len(found.Skipped) != 1 || found.Skipped[0].Directory != filepath.Join(root, "old.default") ||
		!strings.Contains(found.Skipped[0].Reason, "cert8.db") {
		t.Errorf("skipped %+v", found.Skipped)
	}
}

// TestTheProfilesOfLaunchersAreAddedOnce: a --profile in a launcher's Exec
// lines (actions included, quoted or in the --profile= form, ~/ expanded)
// adds its folder, named by the launcher; a folder the profiles already list is
// not added twice, and relative paths are ignored.
func TestTheProfilesOfLaunchersAreAddedOnce(t *testing.T) {
	home := t.TempDir()
	xdg := filepath.Join(home, ".config", "librewolf", "librewolf")
	writeFile(t, filepath.Join(xdg, "profiles.ini"), "[Profile0]\nIsRelative=1\nPath=ox.default\nDefault=1\n")
	makeStore(t, filepath.Join(xdg, "ox.default"))
	work := filepath.Join(home, "my profiles", "work")
	makeStore(t, work)
	makeStore(t, filepath.Join(home, "other.dir"))
	makeStore(t, filepath.Join(home, "fourth"))
	writeFile(t, filepath.Join(home, ".local", "share", "applications", "custom.desktop"),
		"[Desktop Entry]\nName=Navigator Custom\nExec=/usr/bin/custom --profile \""+work+"\" %u\n"+
			"Exec=/usr/bin/custom -profile "+filepath.Join(home, "other.dir")+"\n"+
			"Exec=/usr/bin/custom --profile "+filepath.Join(xdg, "ox.default")+"\n"+
			"Exec=/usr/bin/custom --profile relative.dir\n\n"+
			"[Desktop Action private]\nName=Private\nExec=/usr/bin/custom --profile=~/fourth --private-window\n")

	found := browserstores.Discover(browserstores.NewEnvironment(home, "linux"))
	expectStores(t, home, found.Stores,
		"LibreWolf||/.config/librewolf/librewolf/ox.default|true",
		"Navigator Custom||/my profiles/work|false",
		"Navigator Custom||/other.dir|false",
		"Navigator Custom||/fourth|false",
	)
}

// TestTheFolderOfAMacOrWindowsInstallIsUsed: the Firefox family keeps its
// profiles in the application-data folders, and Chromium's ~/.pki/nssdb is not
// a store there.
func TestTheFolderOfAMacOrWindowsInstallIsUsed(t *testing.T) {
	home := t.TempDir()
	mac := filepath.Join(home, "Library", "Application Support", "librewolf")
	writeFile(t, filepath.Join(mac, "profiles.ini"), "[Profile0]\nIsRelative=1\nPath=mac.default\nDefault=1\n")
	makeStore(t, filepath.Join(mac, "mac.default"))
	makeStore(t, filepath.Join(home, ".pki", "nssdb"))

	found := browserstores.Discover(browserstores.NewEnvironment(home, "darwin"))
	expectStores(t, home, found.Stores, "LibreWolf||/Library/Application Support/librewolf/mac.default|true")

	roaming := filepath.Join(home, "AppData", "Roaming")
	writeFile(t, filepath.Join(roaming, "Mozilla", "Firefox", "profiles.ini"), "[Profile0]\nIsRelative=1\nPath=win.default\nDefault=1\n")
	makeStore(t, filepath.Join(roaming, "Mozilla", "Firefox", "win.default"))
	env := browserstores.NewEnvironment(home, "windows")
	env.AppData = roaming
	expectStores(t, home, browserstores.Discover(env).Stores, "Firefox||/AppData/Roaming/Mozilla/Firefox/win.default|true")

	// Without %APPDATA% there is no folder to look in, and nothing is read from the working directory.
	env.AppData = ""
	if stores := browserstores.Discover(env).Stores; len(stores) != 0 {
		t.Errorf("stores without APPDATA: %v", describe(home, stores))
	}
}

// TestTheSessionFoldersAreReadFromTheEnvironment: XDG variables name the
// session's folders, except inside a Flatpak sandbox, where they point into
// ~/.var/app and the host's browsers are not there.
func TestTheSessionFoldersAreReadFromTheEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG folders are Linux's")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".var", "app", "org.codeberg.simplicer.trebaruna", "data"))
	env, err := browserstores.FromSystem()
	if err != nil {
		t.Fatal(err)
	}
	if env.ConfigHome != filepath.Join(home, "xdg-config") {
		t.Errorf("config folder %s", env.ConfigHome)
	}
	if env.DataHome != filepath.Join(home, ".local", "share") {
		t.Errorf("data folder %s, want the home's default inside a sandbox", env.DataHome)
	}
}
