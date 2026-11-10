package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"codeberg.org/simplicer/trebaruna/src/encryption/application"
	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
	"codeberg.org/simplicer/trebaruna/src/encryption/infrastructure"
)

// runFindRecipient implements `trebaruna recipients find`: a person's
// certificates looked up in an LDAP directory, by e-mail address or name,
// each said to be fit to encrypt for or not, and with --save the fit ones
// kept in the address book.
func runFindRecipient(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("recipients find", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("ldap", "", "the directory: ldap://host/<base> or ldaps://host/<base>")
	base := flags.String("base", "", "where in the directory to search, such as o=Example,c=ES (default: the URL's path)")
	save := flags.Bool("save", false, "keep in the address book every certificate found that can receive envelopes")
	asJSON := flags.Bool("json", false, "machine-readable output")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna recipients find <e-mail address | name> --ldap ldap://host/<base> [--base <dn>] [--save] [--json]")
		flags.PrintDefaults()
	}
	remaining, positional := splitArguments(args, valueFlagsWith("ldap", "base"))
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}
	if len(positional) != 1 || *directory == "" {
		flags.Usage()
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	found, err := application.NewFindRecipient(infrastructure.LDAPDirectory{URL: *directory, Base: *base}, time.Now).Execute(ctx, positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "directory lookup failed: %v\n", err)
		printConnections(stderr)
		return exitInvalid
	}

	var book application.RecipientBook
	if *save {
		if book, err = infrastructure.DefaultRecipientDirectory(); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitInvalid
		}
	}
	type line struct {
		Holder      string `json:"holder"`
		Issuer      string `json:"issuer"`
		Fingerprint string `json:"fingerprint"`
		NotAfter    string `json:"not_after"`
		Usable      bool   `json:"usable"`
		Problem     string `json:"problem,omitempty"`
		Saved       bool   `json:"saved"`
	}
	lines := []line{}
	for _, certificate := range found {
		entry := line{Holder: encryption.SavedFrom(certificate.Certificate, "").Holder, Issuer: certificate.Certificate.Issuer.CommonName,
			Fingerprint: encryption.Fingerprint(certificate.Certificate), NotAfter: certificate.Certificate.NotAfter.UTC().Format(time.RFC3339),
			Usable: certificate.Problem == nil}
		if certificate.Problem != nil {
			entry.Problem = certificate.Problem.Error()
		} else if *save {
			if _, err := application.NewKeepRecipient(book, time.Now).Execute(ctx, certificate.Certificate); err != nil {
				entry.Problem = err.Error()
			} else {
				entry.Saved = true
			}
		}
		lines = append(lines, entry)
	}
	if *asJSON {
		encodeJSONValue(stdout, map[string]any{"certificates": lines, "connections": connections()})
		return exitOK
	}
	if len(lines) == 0 {
		fmt.Fprintf(stdout, "the directory publishes no certificate for %s\n", positional[0])
	}
	for _, entry := range lines {
		state := "can receive envelopes"
		switch {
		case entry.Saved:
			state = "saved in the address book"
		case entry.Problem != "":
			state = entry.Problem
		}
		fmt.Fprintf(stdout, "%s  %s (%s), until %s: %s\n", entry.Fingerprint[:16], entry.Holder, entry.Issuer, entry.NotAfter[:10], state)
	}
	printConnections(stdout)
	return exitOK
}
