package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/localtls"
)

// databaseList collects repeated --nss-db flags.
type databaseList []string

func (d *databaseList) String() string     { return strings.Join(*d, ",") }
func (d *databaseList) Set(v string) error { *d = append(*d, v); return nil }

// runLocalTLS implements `trebaruna afirma local-tls`: the certificate the
// afirma:// WebSocket channel serves on 127.0.0.1, and its root in the
// user's browser stores (ADR-0019, stores found as ADR-0020 says).
func runLocalTLS(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("afirma local-tls", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var databases databaseList
	flags.Var(&databases, "nss-db", "an NSS database to use (repeatable; default: the NSS stores of the browsers found on this computer)")
	directory := flags.String("dir", "", "where the certificate is kept (default: $XDG_CONFIG_HOME/trebaruna/localtls)")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna afirma local-tls status|install|remove [--nss-db dir]")
		flags.PrintDefaults()
	}
	if len(args) == 0 {
		flags.Usage()
		return exitUsage
	}
	action := args[0]
	if err := flags.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if *directory == "" {
		var err error
		if *directory, err = localtls.Directory(); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitInvalid
		}
	}

	// The stores are found where the browsers keep them; --nss-db names others.
	found := localtls.UserStores()
	named := len(databases) > 0
	names := map[string]string{}
	for _, store := range found.Stores {
		names[store.Directory] = store.Name()
		if !named {
			databases = append(databases, store.Directory)
		}
	}
	if action == "remove" {
		// Every store the root went into, even one the browser no longer lists.
		for _, database := range localtls.Recorded(*directory) {
			if !slices.Contains(databases, database) {
				databases = append(databases, database)
			}
		}
	}

	switch action {
	case "status":
		material, err := localtls.Load(*directory)
		if err != nil {
			fmt.Fprintf(stdout, "no certificate made yet (%v)\n", err)
		} else {
			fmt.Fprintf(stdout, "root     %s, until %s\n", material.Fingerprint(), material.Root.NotAfter.Format("2006-01-02"))
		}
		for _, database := range databases {
			state := "not installed"
			if localtls.Installed(database) {
				state = "installed"
			}
			fmt.Fprintf(stdout, "store    %s: %s\n", describeStore(database, names), state)
		}
		if !named {
			for _, skipped := range found.Skipped {
				fmt.Fprintf(stdout, "skipped  %s: %s\n", skipped.Directory, skipped.Reason)
			}
		}
		return exitOK
	case "install":
		material, err := localtls.Load(*directory)
		if err != nil || material.Expired(time.Now()) {
			if material, err = localtls.Generate(*directory, time.Now()); err != nil {
				fmt.Fprintf(stderr, "%v\n", err)
				return exitInvalid
			}
		}
		if len(databases) == 0 {
			fmt.Fprintln(stderr, "no browser certificate store found for this user (Firefox family, LibreWolf, Chromium); name one with --nss-db <dir>")
			return exitInvalid
		}
		if err := localtls.Install(material, databases); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitInvalid
		}
		if err := localtls.Remember(*directory, databases); err != nil {
			fmt.Fprintf(stderr, "the root is installed, but its stores could not be recorded for removal: %v\n", err)
			return exitInvalid
		}
		fmt.Fprintf(stdout, "installed the root %s\n", material.Fingerprint())
		fmt.Fprintln(stdout, "  it signed trebaruna's certificate for 127.0.0.1 and its key was destroyed: it can sign nothing else,")
		fmt.Fprintln(stdout, "  and it is limited to 127.0.0.1 and localhost; `trebaruna afirma local-tls remove` takes it out")
		for _, database := range databases {
			fmt.Fprintf(stdout, "  in %s\n", describeStore(database, names))
		}
		return exitOK
	case "remove":
		if err := localtls.Remove(databases); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitInvalid
		}
		if err := os.RemoveAll(*directory); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitInvalid
		}
		fmt.Fprintln(stdout, "removed the root from the stores and the certificate from this computer")
		return exitOK
	}
	flags.Usage()
	return exitUsage
}

// describeStore names a store by its browser when it is known, with its folder.
func describeStore(database string, names map[string]string) string {
	if name, known := names[database]; known {
		return name + " at " + database
	}
	return database
}
