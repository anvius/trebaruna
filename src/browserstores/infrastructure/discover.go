package infrastructure

import (
	"os"
	"path/filepath"

	"codeberg.org/simplicer/trebaruna/src/browserstores/domain"
)

// skipFunc records a folder that was not used, and why.
type skipFunc func(directory, reason string)

// Discover lists the NSS stores of the user in env. Within a program the
// default profile comes first, then the others; the native installs come
// before Snap and Flatpak, and the stores a launcher names come last. A folder
// is listed once, however many places lead to it.
func Discover(env Environment) domain.Discovery {
	var found domain.Discovery
	listed := map[string]bool{}
	add := func(store domain.Store) {
		if key := identity(store.Directory); !listed[key] {
			listed[key] = true
			found.Stores = append(found.Stores, store)
		}
	}
	skip := func(directory, reason string) {
		found.Skipped = append(found.Skipped, domain.Skipped{Directory: directory, Reason: reason})
	}

	for _, program := range layouts(env) {
		if program.shared != "" {
			if filepath.IsAbs(program.shared) && holdsStore(program.shared, skip) {
				add(domain.Store{Browser: program.browser, Packaging: program.packaging, Directory: program.shared})
			}
			continue
		}
		for _, folder := range program.profiles {
			if !filepath.IsAbs(folder) {
				continue
			}
			for _, profile := range readProfiles(folder, skip) {
				if holdsStore(profile.directory, skip) {
					add(domain.Store{
						Browser:   program.browser,
						Packaging: program.packaging,
						Profile:   filepath.Base(profile.directory),
						Directory: profile.directory,
						Default:   profile.isDefault,
					})
				}
			}
		}
	}
	for _, store := range desktopStores(env, skip) {
		add(store)
	}
	return found
}

// holdsStore reports whether a folder holds a store this program reads: a
// cert9.db. A folder with only a legacy cert8.db is reported as skipped.
func holdsStore(directory string, skip skipFunc) bool {
	if _, err := os.Stat(filepath.Join(directory, "cert9.db")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(directory, "cert8.db")); err == nil {
		skip(directory, "a legacy cert8.db store, which trebaruna does not read")
	}
	return false
}

// identity is the folder a store is known by, so that one folder reached by
// two paths is listed once.
func identity(directory string) string {
	if resolved, err := filepath.EvalSymlinks(directory); err == nil {
		return resolved
	}
	return filepath.Clean(directory)
}
