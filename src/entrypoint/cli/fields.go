package cli

// `trebaruna fields` — the empty signature fields of a PDF form, the ones
// `sign --field` signs in.

import (
	"flag"
	"fmt"
	"io"
	"os"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/pdffield"
)

func runFields(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("fields", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "machine-readable output")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna fields <document.pdf> [--json]")
		flags.PrintDefaults()
	}
	remaining, positional := splitArguments(args, map[string]bool{})
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}
	if len(positional) != 1 {
		flags.Usage()
		return exitUsage
	}
	content, err := os.ReadFile(positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	fields, err := pdffield.EmptyFields(content)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}

	if *asJSON {
		listed := make([]map[string]any, 0, len(fields))
		for _, field := range fields {
			listed = append(listed, map[string]any{"name": field.Name, "page": field.Page, "box": field.Rect})
		}
		encodeJSONValue(stdout, map[string]any{"path": positional[0], "fields": listed})
		return exitOK
	}
	if len(fields) == 0 {
		fmt.Fprintln(stdout, "no empty signature field")
		return exitOK
	}
	for _, field := range fields {
		fmt.Fprintf(stdout, "%s  page %d  box %.0f,%.0f,%.0f,%.0f  (%.0fx%.0f pt)\n", field.Name, field.Page,
			field.Rect[0], field.Rect[1], field.Rect[2], field.Rect[3], field.Width(), field.Height())
	}
	return exitOK
}
