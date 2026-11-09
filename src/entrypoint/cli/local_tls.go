package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
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
// user's browser stores (ADR-0019).
func runLocalTLS(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("afirma local-tls", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var databases databaseList
	flags.Var(&databases, "nss-db", "an NSS database to use (repeatable; default: the user's Firefox profiles and ~/.pki/nssdb)")
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
	if len(databases) == 0 {
		databases = localtls.UserDatabases()
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
			fmt.Fprintf(stdout, "store    %s: %s\n", database, state)
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
			fmt.Fprintln(stderr, "no browser certificate store found for this user (Firefox profiles, ~/.pki/nssdb)")
			return exitInvalid
		}
		if err := localtls.Install(material, databases); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitInvalid
		}
		fmt.Fprintf(stdout, "installed the root %s\n", material.Fingerprint())
		fmt.Fprintln(stdout, "  it signed trebaruna's certificate for 127.0.0.1 and its key was destroyed: it can sign nothing else,")
		fmt.Fprintln(stdout, "  and it is limited to 127.0.0.1 and localhost; `trebaruna afirma local-tls remove` takes it out")
		for _, database := range databases {
			fmt.Fprintf(stdout, "  in %s\n", database)
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
