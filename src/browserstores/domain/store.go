// Package domain says what the certificate stores of a user's browsers and
// mail clients are, once found on this computer (ADR-0020).
package domain

// Store is an NSS certificate store a browser or a mail client keeps on disk:
// its folder holds cert9.db and key4.db. trebaruna opens it in place to sign,
// or adds the local channel's root to it (ADR-0019).
type Store struct {
	// Browser is the program's name as its users know it: "Firefox",
	// "LibreWolf", "Thunderbird". The store every Chromium-based browser shares
	// on Linux is "Chromium".
	Browser string
	// Packaging names the package when it is not the native install, as
	// "snap" or "flatpak io.gitlab.librewolf-community"; empty otherwise.
	Packaging string
	// Profile is the folder name of a Firefox-style profile; empty for a store
	// shared by a whole home folder, as Chromium's ~/.pki/nssdb is.
	Profile string
	// Directory is the folder that holds the store.
	Directory string
	// Default marks the profile the program opens first: the one its
	// installs.ini (or an [Install…] section) names, or the one marked Default=1.
	Default bool
}

// Name says whose store it is, for messages and listings.
func (s Store) Name() string {
	name := s.Browser
	if s.Packaging != "" {
		name += " " + s.Packaging
	}
	if s.Profile == "" {
		return name + " (shared NSS store)"
	}
	return name + " (" + s.Profile + ")"
}

// Browsing reports whether the store belongs to a browser rather than to a
// mail client: what the --firefox flag names.
func (s Store) Browsing() bool { return s.Browser != "Thunderbird" }

// Discovery is what was found on the computer: the stores, and the folders
// that look like stores but are not used, with the reason.
type Discovery struct {
	Stores  []Store
	Skipped []Skipped
}

// Skipped is a folder that was not used, and why.
type Skipped struct {
	Directory string
	Reason    string
}
