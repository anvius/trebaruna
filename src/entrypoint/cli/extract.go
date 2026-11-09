package cli

// `trebaruna extract` — take the signed document out of a .p7m envelope, or out
// of several nested ones (contratto.pdf.p7m.p7m), in DER, BER, PEM or Base64.

import (
	"flag"
	"fmt"
	"io"

	"codeberg.org/simplicer/trebaruna/src/verification/application"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func runExtract(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("extract", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		output = flags.String("out", "", "where to write the document (default: the envelope's name without .p7m)")
		asJSON = flags.Bool("json", false, "machine-readable output")
	)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna extract <document.p7m> [--out path] [--json]")
		flags.PrintDefaults()
	}

	envelope, remaining, err := extractDocument("extract", args)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		flags.Usage()
		return exitUsage
	}
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}

	extracted, err := application.NewExtractDocument(verificationinfra.LocalFiles{}, verificationinfra.CMSEnvelopes{}).
		Execute(application.ExtractRequest{Envelope: envelope, Output: *output})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}

	if *asJSON {
		encodeJSONValue(stdout, map[string]any{
			"path": extracted.Path, "layers": extracted.Layers, "size_bytes": extracted.Size,
		})
		return exitOK
	}
	fmt.Fprintf(stdout, "extracted %s\n", extracted.Path)
	fmt.Fprintf(stdout, "  envelopes opened  %d\n", extracted.Layers)
	fmt.Fprintf(stdout, "  size              %d bytes\n", extracted.Size)
	fmt.Fprintln(stdout, "  note              extraction does not verify; run `trebaruna verify` on the envelope")
	return exitOK
}
