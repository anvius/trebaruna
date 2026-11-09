package localtls

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrNoCertutil means NSS's certutil is not installed.
var ErrNoCertutil = errors.New("certutil (NSS tools, package libnss3-tools or nss-tools) is needed to change the browsers' certificate stores")

// UserDatabases are the user's NSS certificate databases: Chromium's and
// Chrome's (~/.pki/nssdb), and each Firefox profile, also as Snap and
// Flatpak install them. Only databases that exist are listed.
func UserDatabases() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	candidates := []string{
		filepath.Join(home, ".pki", "nssdb"),
		filepath.Join(home, "snap", "chromium", "current", ".pki", "nssdb"),
	}
	for _, profiles := range []string{
		filepath.Join(home, ".mozilla", "firefox"),
		filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
		filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
	} {
		entries, _ := os.ReadDir(profiles)
		for _, entry := range entries {
			if entry.IsDir() {
				candidates = append(candidates, filepath.Join(profiles, entry.Name()))
			}
		}
	}
	var databases []string
	for _, candidate := range candidates {
		if _, err := os.Stat(filepath.Join(candidate, "cert9.db")); err == nil {
			databases = append(databases, candidate)
		}
	}
	return databases
}

// Install trusts the root, as an authority for servers, in each database.
func Install(material Material, databases []string) error {
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		return ErrNoCertutil
	}
	file, err := os.CreateTemp("", "trebaruna-root-*.pem")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(material.RootPEM()); err != nil {
		file.Close()
		return err
	}
	file.Close()
	for _, database := range databases {
		// A root of an earlier install goes first: the nickname names one.
		_ = exec.Command(certutil, "-D", "-n", Nickname, "-d", "sql:"+database).Run()
		if output, err := exec.Command(certutil, "-A", "-n", Nickname, "-t", "C,,", "-i", file.Name(),
			"-d", "sql:"+database).CombinedOutput(); err != nil {
			return fmt.Errorf("install in %s: %v: %s", database, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

// Remove takes the root out of each database where it is.
func Remove(databases []string) error {
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		return ErrNoCertutil
	}
	for _, database := range databases {
		if !Installed(database) {
			continue
		}
		if output, err := exec.Command(certutil, "-D", "-n", Nickname, "-d", "sql:"+database).CombinedOutput(); err != nil {
			return fmt.Errorf("remove from %s: %v: %s", database, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

// Installed reports whether a database holds the root.
func Installed(database string) bool {
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		return false
	}
	return exec.Command(certutil, "-L", "-n", Nickname, "-d", "sql:"+database).Run() == nil
}
