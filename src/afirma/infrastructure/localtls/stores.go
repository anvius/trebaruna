package localtls

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/browserstores/domain"
	browserstores "codeberg.org/simplicer/trebaruna/src/browserstores/infrastructure"
)

// ErrNoNSS means the NSS library that reads and writes the browsers' stores is
// not available: softokn3 is not installed, or this build has no cgo. Nothing is
// then known about a store, so the status says it cannot check it.
var ErrNoNSS = errors.New("the NSS library (softokn3: package libnss3, or nss on Fedora) is needed to read the browsers' certificate stores, and trebaruna must be built with cgo")

// ErrNoStore means the folder holds no NSS store (cert9.db).
var ErrNoStore = errors.New("no NSS store (cert9.db) in this folder")

// Presence is whether a store holds the local channel's root.
type Presence int

const (
	// Absent: the store is readable and holds no root of trebaruna's.
	Absent Presence = iota
	// Present: the store trusts the root as an authority for servers.
	Present
)

// recordedStores is the file beside the certificate that lists the databases
// the root was installed in. Removal takes the root out of each of them, even
// one the browser has since dropped from its profiles.
const recordedStores = "stores"

// Available reports whether the NSS library is there to read and change stores.
func Available() bool {
	return available()
}

// UserStores finds the NSS stores of the user's browsers and mail clients, and
// the folders that were skipped (browserstores, ADR-0020). Nothing is found
// when the user has no home folder.
func UserStores() domain.Discovery {
	env, err := browserstores.FromSystem()
	if err != nil {
		return domain.Discovery{}
	}
	return browserstores.Discover(env)
}

// Remember records, beside the certificate, the databases the root went into.
func Remember(directory string, databases []string) error {
	known := Recorded(directory)
	for _, database := range databases {
		if !slices.Contains(known, database) {
			known = append(known, database)
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, recordedStores), []byte(strings.Join(known, "\n")+"\n"), 0o600)
}

// Recorded lists the databases the root was installed in, as Remember recorded them.
func Recorded(directory string) []string {
	content, err := os.ReadFile(filepath.Join(directory, recordedStores))
	if err != nil {
		return nil
	}
	var databases []string
	for _, line := range strings.Split(string(content), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			databases = append(databases, line)
		}
	}
	return databases
}

// CreateStore makes an empty NSS store in a folder, as certutil -N does, or
// opens the one there. Installing needs a store already made.
func CreateStore(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return makeStore(directory)
}

// Check reports whether a store holds the root. The error says why the store
// cannot be checked: it has no NSS store in it, or the NSS library is missing.
func Check(database string) (Presence, error) {
	if err := requireStore(database); err != nil {
		return Absent, err
	}
	return hasRoot(database)
}

// Install trusts the root, as an authority for servers, in each database. A
// root of an earlier install is replaced.
func Install(material Material, databases []string) error {
	for _, database := range databases {
		if err := requireStore(database); err != nil {
			return fmt.Errorf("install in %s: %w", database, err)
		}
		if err := writeRoot(database, material.Root); err != nil {
			return fmt.Errorf("install in %s: %w", database, err)
		}
	}
	return nil
}

// Remove takes the root out of each database where it is. A database that
// holds no store is passed over: there is nothing to take out of it.
func Remove(databases []string) error {
	for _, database := range databases {
		if err := requireStore(database); err != nil {
			if errors.Is(err, ErrNoStore) {
				continue
			}
			return fmt.Errorf("remove from %s: %w", database, err)
		}
		if err := removeRoot(database); err != nil {
			return fmt.Errorf("remove from %s: %w", database, err)
		}
	}
	return nil
}

// requireStore is ErrNoStore unless the folder holds an NSS store.
func requireStore(database string) error {
	if _, err := os.Stat(filepath.Join(database, "cert9.db")); err != nil {
		return fmt.Errorf("%w: %s", ErrNoStore, database)
	}
	return nil
}
