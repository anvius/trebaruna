package infrastructure

import (
	"os"
	"runtime"
	"strings"

	browserdomain "codeberg.org/simplicer/trebaruna/src/browserstores/domain"
	browserstores "codeberg.org/simplicer/trebaruna/src/browserstores/infrastructure"
)

// SoftwareStore is a certificate store a program keeps on disk in the NSS
// format, opened in place through NSS's own PKCS#11 module: the certificate
// and its key stay where Firefox (or Chromium, or Thunderbird) put them, and
// nothing is exported.
type SoftwareStore struct {
	// Name says whose store it is, for messages and listings.
	Name string
	// Browser is the program the store belongs to as its users know it
	// ("LibreWolf"); the window names it in the primary password's label.
	Browser string
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

// NSSStores lists the NSS stores of the user on system, as the browserstores
// module finds them: the profiles of the browsers, then the store Chromium
// shares on Linux. Only stores that hold a database are listed.
func NSSStores(home, system string) []SoftwareStore {
	env := browserstores.NewEnvironment(home, system)
	env.AppData = os.Getenv("APPDATA")
	var stores []SoftwareStore
	for _, store := range browserstores.Discover(env).Stores {
		stores = append(stores, softwareStore(store))
	}
	return stores
}

// FirefoxStore is the store of the profile a browser of the Firefox family
// (Firefox, LibreWolf, Waterfox, ...) starts with, or false when this user has
// none. A mail client's store is not one.
func FirefoxStore() (SoftwareStore, bool) {
	env, err := browserstores.FromSystem()
	if err != nil {
		return SoftwareStore{}, false
	}
	for _, store := range browserstores.Discover(env).Stores {
		if store.Profile != "" && store.Browsing() {
			return softwareStore(store), true
		}
	}
	return SoftwareStore{}, false
}

// softwareStore is a found store as the signing code opens it.
func softwareStore(store browserdomain.Store) SoftwareStore {
	return SoftwareStore{Name: store.Name(), Browser: store.Browser, Directory: store.Directory}
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
