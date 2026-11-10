package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// runConvert turns a text, spreadsheet or presentation document into the
// PDF LibreOffice prints of it, beside the document unless --out says
// otherwise: the PDF to read before signing it, or to sign with sign.
func runConvert(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("convert", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("out", "", "where the PDF goes (default: beside the document, ending in .pdf)")
	force := flags.Bool("force", false, "replace an existing file at the output")
	asJSON := flags.Bool("json", false, "machine-readable output")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna convert <document> [--out file.pdf] [--force] [--json]")
		fmt.Fprintln(stderr, "  prints a text, spreadsheet or presentation to PDF with LibreOffice")
		flags.PrintDefaults()
	}
	path, remaining, err := extractDocument("convert", args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		flags.Usage()
		return exitUsage
	}
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}
	document, err := domain.OpenDocument(path)
	if err != nil {
		fmt.Fprintf(stderr, "invalid document: %v\n", err)
		return exitUsage
	}
	written, err := Conversion().Execute(context.Background(), application.ConversionRequest{
		Document: document, OutputPath: *output, Overwrite: *force})
	if err != nil {
		fmt.Fprintf(stderr, "conversion failed: %v\n", err)
		return exitInvalid
	}
	if *asJSON {
		encodeJSONLine(stdout, map[string]string{"document": document.Path(), "pdf": written})
		return exitOK
	}
	fmt.Fprintf(stdout, "PDF written to %s\n", written)
	return exitOK
}
