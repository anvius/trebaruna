package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// errNoFirefoxProfile means this user has no Firefox profile with a store.
var errNoFirefoxProfile = errors.New("no Firefox profile with a certificate store was found; " +
	"name the store's directory with --nss-db <dir>")

// storeOptions are the flags that name an NSS software store: the Firefox
// profile Firefox starts with, or any NSS database directory.
type storeOptions struct {
	firefox   bool
	directory string
}

// chosen reports whether a store was named.
func (o storeOptions) chosen() bool { return o.firefox || o.directory != "" }

// resolve finds the store and NSS's module. The store opens read-only: the
// browser's database is never changed.
func (o storeOptions) resolve() (store infrastructure.SoftwareStore, module string, err error) {
	switch {
	case o.firefox && o.directory != "":
		return store, "", errors.New("use either --firefox or --nss-db, not both")
	case o.firefox:
		found, ok := infrastructure.FirefoxStore()
		if !ok {
			return store, "", errNoFirefoxProfile
		}
		store = found
	default:
		absolute, err := filepath.Abs(o.directory)
		if err != nil {
			return store, "", err
		}
		if _, err := os.Stat(filepath.Join(absolute, "cert9.db")); err != nil {
			return store, "", fmt.Errorf("%s holds no NSS certificate store (cert9.db)", absolute)
		}
		store = infrastructure.SoftwareStore{Name: "NSS (" + absolute + ")", Directory: absolute}
	}

	module = infrastructure.NSSModule()
	if module == "" {
		return store, "", errors.New("NSS was not found on this system: install it (libnss3) to use a Firefox store")
	}
	return store, module, nil
}
