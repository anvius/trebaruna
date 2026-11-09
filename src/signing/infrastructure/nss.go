package infrastructure

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SoftwareStore is a certificate store a program keeps on disk in the NSS
// format, opened in place through NSS's own PKCS#11 module: the certificate
// and its key stay where Firefox (or Chromium, or Thunderbird) put them, and
// nothing is exported.
type SoftwareStore struct {
	// Name says whose store it is, for messages and listings.
	Name string
	// Directory holds cert9.db and key4.db.
	Directory string
}

// Parameters are the NSS initialisation parameters that open the store
// read-only, so trebaruna never changes the browser's database.
func (s SoftwareStore) Parameters() string {
	quote := "'"
	if strings.Contains(s.Directory, "'") {
		quote = `"`
	}
	return "configdir=" + quote + "sql:" + s.Directory + quote +
		" certPrefix='' keyPrefix='' secmod='secmod.db' flags=readOnly"
}

// NSSStores lists the NSS stores of the user: the Firefox profiles, the one
// Firefox starts with first, then the shared store Chromium uses on Linux.
// Only directories that hold a database are listed.
func NSSStores(home, system string) []SoftwareStore {
	var stores []SoftwareStore
	for _, root := range firefoxRoots(home, system) {
		for _, profile := range firefoxProfiles(root) {
			stores = appendStore(stores, SoftwareStore{Name: "Firefox (" + filepath.Base(profile) + ")", Directory: profile})
		}
	}
	if system == "linux" {
		stores = appendStore(stores, SoftwareStore{Name: "NSS (" + filepath.Join("~", ".pki", "nssdb") + ")",
			Directory: filepath.Join(home, ".pki", "nssdb")})
	}
	return stores
}

// FirefoxStore is the store of the profile Firefox starts with, or false
// when this user has none.
func FirefoxStore() (SoftwareStore, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return SoftwareStore{}, false
	}
	for _, store := range NSSStores(home, runtime.GOOS) {
		if strings.HasPrefix(store.Name, "Firefox") {
			return store, true
		}
	}
	return SoftwareStore{}, false
}

// appendStore adds a store that holds a database and is not listed yet.
func appendStore(stores []SoftwareStore, store SoftwareStore) []SoftwareStore {
	if _, err := os.Stat(filepath.Join(store.Directory, "cert9.db")); err != nil {
		return stores
	}
	for _, listed := range stores {
		if listed.Directory == store.Directory {
			return stores
		}
	}
	return append(stores, store)
}

// firefoxRoots are the directories that hold profiles.ini on each system,
// including the sandboxed packages of Linux.
func firefoxRoots(home, system string) []string {
	switch system {
	case "windows":
		return []string{filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox")}
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", "Firefox")}
	default:
		return []string{
			filepath.Join(home, ".mozilla", "firefox"),
			filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
			filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
		}
	}
}

// firefoxProfiles reads profiles.ini: the profile an installation starts with
// first ([Install…] Default=), then the one marked Default=1, then the rest.
func firefoxProfiles(root string) []string {
	file, err := os.Open(filepath.Join(root, "profiles.ini"))
	if err != nil {
		return nil
	}
	defer file.Close()

	type profile struct {
		path       string
		relative   bool
		preferred  bool
		installing bool
	}
	var profiles []profile
	var current *profile
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "["):
			profiles = append(profiles, profile{relative: true, installing: strings.HasPrefix(line, "[Install")})
			current = &profiles[len(profiles)-1]
		case current == nil:
		case strings.HasPrefix(line, "Path="):
			current.path = strings.TrimPrefix(line, "Path=")
		case strings.HasPrefix(line, "IsRelative="):
			current.relative = strings.TrimPrefix(line, "IsRelative=") == "1"
		case line == "Default=1":
			current.preferred = true
		case current.installing && strings.HasPrefix(line, "Default="):
			current.path = strings.TrimPrefix(line, "Default=")
		}
	}

	resolve := func(entry profile) string {
		if entry.installing || entry.relative {
			return filepath.Join(root, filepath.FromSlash(entry.path))
		}
		return entry.path
	}
	var ordered []string
	for _, pass := range []func(profile) bool{
		func(entry profile) bool { return entry.installing },
		func(entry profile) bool { return !entry.installing && entry.preferred },
		func(entry profile) bool { return !entry.installing && !entry.preferred },
	} {
		for _, entry := range profiles {
			if entry.path != "" && pass(entry) {
				ordered = append(ordered, resolve(entry))
			}
		}
	}
	return ordered
}

// NSSModule returns NSS's PKCS#11 module (softokn3) on this system, or the
// empty string when NSS is not installed.
func NSSModule() string {
	for _, location := range NSSLocations(runtime.GOOS, runtime.GOARCH) {
		if info, err := os.Stat(location); err == nil && !info.IsDir() {
			return location
		}
	}
	return ""
}

// NSSLocations lists where softokn3 lives on a system and architecture: the
// system NSS first, then the copy Firefox ships.
func NSSLocations(system, architecture string) []string {
	switch system {
	case "windows":
		return []string{
			`C:\Program Files\Mozilla Firefox\softokn3.dll`,
			`C:\Program Files (x86)\Mozilla Firefox\softokn3.dll`,
		}
	case "darwin":
		return []string{
			"/opt/homebrew/lib/libsoftokn3.dylib",
			"/usr/local/lib/libsoftokn3.dylib",
			"/Applications/Firefox.app/Contents/MacOS/libsoftokn3.dylib",
		}
	}

	var locations []string
	if triplet, known := debianTriplets[architecture]; known {
		locations = append(locations,
			"/usr/lib/"+triplet+"/libsoftokn3.so",
			"/usr/lib/"+triplet+"/nss/libsoftokn3.so")
	}
	return append(locations,
		"/usr/lib64/libsoftokn3.so",
		"/usr/lib64/nss/libsoftokn3.so",
		"/usr/lib/libsoftokn3.so",
		"/usr/lib/nss/libsoftokn3.so",
		"/usr/local/lib/libsoftokn3.so",
		"/usr/lib/firefox/libsoftokn3.so")
}
