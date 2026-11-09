package cli

// `trebaruna about` — what this binary is, where it came from and what it
// contains, so anyone can rebuild it from the same revision and compare.

import (
	"flag"
	"fmt"
	"io"

	signinginfra "codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

func runAbout(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("about", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "machine-readable output")
	asSBOM := flags.Bool("sbom", false, "CycloneDX 1.5 software bill of materials")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	build := transparency.Describe(version, signinginfra.PKCS11Available)
	if *asSBOM {
		encodeJSONValue(stdout, transparency.BillOfMaterials(build))
		return exitOK
	}
	if *asJSON {
		encodeJSONValue(stdout, build)
		return exitOK
	}

	fmt.Fprintf(stdout, "trebaruna %s (%s, %s)\n", build.Version, build.Platform, build.Go)
	fmt.Fprintf(stdout, "  licence   %s\n", build.License)
	fmt.Fprintf(stdout, "  source    %s\n", build.BuiltFrom)
	if build.Revision != "" {
		modified := ""
		if build.Modified {
			modified = " (with local changes)"
		}
		fmt.Fprintf(stdout, "  revision  %s%s\n", build.Revision, modified)
	}
	cards := "no (static build without cgo)"
	if build.PKCS11 {
		cards = "yes (PKCS#11)"
	}
	fmt.Fprintf(stdout, "  cards     %s\n", cards)
	fmt.Fprintf(stdout, "\ndependencies (%d), all linked into this binary:\n", len(build.Dependencies))
	for _, dependency := range build.Dependencies {
		fmt.Fprintf(stdout, "  %-48s %-36s %s\n", dependency.Path, dependency.Version, dependency.License)
	}
	return exitOK
}
