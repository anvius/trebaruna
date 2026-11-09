package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/encryption/application"
	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
	"codeberg.org/simplicer/trebaruna/src/encryption/infrastructure"
)

// runRecipients implements `trebaruna recipients list|add|remove`: the
// address book of certificates to encrypt for.
func runRecipients(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, "usage: trebaruna recipients list [--json]")
		fmt.Fprintln(stderr, "       trebaruna recipients add <certificate> [--json]")
		fmt.Fprintln(stderr, "       trebaruna recipients remove <fingerprint start | holder> [--json]")
		fmt.Fprintln(stderr, "  encrypt for a saved recipient with: trebaruna encrypt <file> --to saved:<fingerprint start | holder>")
		return exitUsage
	}
	if len(args) == 0 {
		return usage()
	}
	action, rest := args[0], args[1:]
	asJSON := false
	var positional []string
	for _, argument := range rest {
		if argument == "--json" {
			asJSON = true
			continue
		}
		positional = append(positional, argument)
	}
	book, err := infrastructure.DefaultRecipientDirectory()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	fail := func(err error) int {
		if asJSON {
			encodeJSONValue(stdout, map[string]any{"error": err.Error()})
		}
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}

	switch {
	case action == "list" && len(positional) == 0:
		saved, err := application.NewListSavedRecipients(book).Execute(context.Background())
		if err != nil {
			return fail(err)
		}
		if asJSON {
			lines := make([]map[string]any, 0, len(saved))
			for _, recipient := range saved {
				lines = append(lines, recipientJSON(recipient))
			}
			encodeJSONValue(stdout, map[string]any{"recipients": lines})
			return exitOK
		}
		if len(saved) == 0 {
			fmt.Fprintln(stdout, "no saved recipients: add one with `trebaruna recipients add <certificate>`")
		}
		for _, recipient := range saved {
			fmt.Fprintf(stdout, "%s  %s  until %s\n", recipient.Fingerprint[:16], recipient.Holder, recipient.NotAfter.Format("2006-01-02"))
		}
		return exitOK
	case action == "add" && len(positional) == 1:
		certificate, err := readCertificateFile(positional[0])
		if err != nil {
			return fail(err)
		}
		recipient, err := application.NewKeepRecipient(book, time.Now).Execute(context.Background(), certificate)
		if err != nil {
			return fail(err)
		}
		if asJSON {
			encodeJSONValue(stdout, recipientJSON(recipient))
			return exitOK
		}
		fmt.Fprintf(stdout, "saved  %s  %s\n", recipient.Holder, recipient.Fingerprint[:16])
		return exitOK
	case action == "remove" && len(positional) == 1:
		recipient, err := application.NewForgetRecipient(book).Execute(context.Background(), positional[0])
		if err != nil {
			return fail(err)
		}
		if asJSON {
			encodeJSONValue(stdout, map[string]any{"removed": recipientJSON(recipient)})
			return exitOK
		}
		fmt.Fprintf(stdout, "removed  %s  %s\n", recipient.Holder, recipient.Fingerprint[:16])
		return exitOK
	}
	return usage()
}

func recipientJSON(recipient encryption.SavedRecipient) map[string]any {
	return map[string]any{"holder": recipient.Holder, "fingerprint": recipient.Fingerprint,
		"not_after": recipient.NotAfter.UTC().Format(time.RFC3339), "path": recipient.Location}
}

// savedPrefix marks a --to that names a saved recipient instead of a file.
const savedPrefix = "saved:"

// recipientPath resolves --to: a certificate file, or saved:<who> from the
// address book.
func recipientPath(value string) (string, error) {
	wanted, saved := strings.CutPrefix(value, savedPrefix)
	if !saved {
		return value, nil
	}
	book, err := infrastructure.DefaultRecipientDirectory()
	if err != nil {
		return "", err
	}
	all, err := application.NewListSavedRecipients(book).Execute(context.Background())
	if err != nil {
		return "", err
	}
	recipient, err := encryption.Pick(all, wanted)
	if err != nil {
		return "", err
	}
	return recipient.Location, nil
}
