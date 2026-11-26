package localtls

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/browserstores/domain"
	browserstores "codeberg.org/simplicer/trebaruna/src/browserstores/infrastructure"
)

// ErrNoCertutil means NSS's certutil is not installed.
var ErrNoCertutil = errors.New("certutil (NSS tools, package libnss3-tools or nss-tools) is needed to change the browsers' certificate stores")

// recordedStores is the file beside the certificate that lists the databases
// the root was installed in. Removal takes the root out of each of them, even
// one the browser has since dropped from its profiles.
const recordedStores = "stores"

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
