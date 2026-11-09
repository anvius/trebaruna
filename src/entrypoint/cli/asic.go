package cli

// ASiC containers (ETSI EN 319 162-1): a ZIP holding the document and,
// under META-INF, its detached signature.
//
// A container keeps the signed file and its signature together, which avoids
// the classic "I sent the PDF but forgot the signature". This command packs an
// existing detached CAdES signature (.p7s) with its document into an ASiC-S.
// XML signatures and ASiC-E containers are made in one step by
// `sign --asic`: an XML signature must be written inside the container's
// asic:XAdESSignatures root, whose namespace its canonical form includes,
// and ASiC-E needs a signature over every file.

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/asic"
)

// runAsic implements `trebaruna asic <document> <signature.p7s>`.
func runAsic(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("asic", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		output  = flags.String("out", "", "output file (default: <document>.asics)")
		kind    = flags.String("type", "s", "container type: s (ASiC-S); ASiC-E is made by sign --asic")
		extract = flags.String("extract", "", "extract this container to a directory instead of building one")
	)

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna asic <document> <signature.p7s> [--out file.asics]")
		fmt.Fprintln(stderr, "       trebaruna asic --extract container.asics [--out directory]")
		flags.PrintDefaults()
	}

	// Flags may come after the positional arguments, which Go's flag package
	// does not support: split them first so `asic a.pdf a.pdf.p7s --out x` works.
	flagArguments, positional := splitArguments(args, map[string]bool{
		"-out": true, "--out": true, "-type": true, "--type": true,
		"-extract": true, "--extract": true,
	})

	if err := flags.Parse(flagArguments); err != nil {
		return exitUsage
	}

	if *extract != "" {
		return extractAsic(*extract, *output, stdout, stderr)
	}

	if len(positional) < 2 {
		flags.Usage()
		return exitUsage
	}
	if container, err := domain.ParseContainer(*kind); err != nil || container != domain.ASiCS {
		fmt.Fprintln(stderr, "only ASiC-S is packed from an existing signature; an ASiC-E container is signed in one step: trebaruna sign --asic e")
		return exitUsage
	}

	document, signature := positional[0], positional[1]
	if err := packableSignature(signature); err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	destination := *output
	if destination == "" {
		destination = document + domain.ASiCS.Extension()
	}

	if err := buildAsic(destination, document, signature); err != nil {
		fmt.Fprintf(stderr, "cannot build the container: %v\n", err)
		return exitInvalid
	}

	fmt.Fprintf(stdout, "built %s\n", destination)
	fmt.Fprintf(stdout, "  mimetype  %s\n", domain.ASiCS.MediaType())
	fmt.Fprintf(stdout, "  document  %s\n", filepath.Base(document))
	fmt.Fprintf(stdout, "  signature %s\n", domain.ASiCS.SignatureEntry(domain.Cades))
	return exitOK
}

// packableSignature accepts a detached CAdES signature and explains the rest.
func packableSignature(path string) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".p7s":
		return nil
	case ".p7m":
		return fmt.Errorf("%s carries the document inside it; an ASiC container holds a detached signature: sign with --detached (.p7s), or in one step with --asic s", path)
	case ".xsig", ".xml":
		return fmt.Errorf("an XML signature for a container is written inside it; sign in one step: trebaruna sign %s --format xades --asic s", "<document>")
	}
	return fmt.Errorf("%s is not a detached CAdES signature (.p7s)", path)
}

// buildAsic writes the ASiC-S container: the document at the root, the
// signature as META-INF/signature.p7s. The file is written whole, then
// renamed, so a failure leaves no half container.
func buildAsic(destination, document, signature string) error {
	documentContent, err := os.ReadFile(document)
	if err != nil {
		return fmt.Errorf("read %q: %w", document, err)
	}
	signatureContent, err := os.ReadFile(signature)
	if err != nil {
		return fmt.Errorf("read %q: %w", signature, err)
	}
	container, err := asic.Write(domain.ASiCS.MediaType(), []asic.Entry{
		{Name: filepath.Base(document), Content: documentContent},
		{Name: domain.ASiCS.SignatureEntry(domain.Cades), Content: signatureContent},
	})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".asic-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(container); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), destination)
}

// extractAsic unpacks a container.
//
// Extraction refuses absolute paths and "..", which is the zip-slip defence: a
// malicious container must not be able to write outside the target directory.
func extractAsic(container, directory string, stdout, stderr io.Writer) int {
	if directory == "" {
		directory = strings.TrimSuffix(filepath.Base(container), filepath.Ext(container)) + "_extracted"
	}

	reader, err := zip.OpenReader(container)
	if err != nil {
		fmt.Fprintf(stderr, "open %q: %v\n", container, err)
		return exitInvalid
	}
	defer func() { _ = reader.Close() }()

	if err := os.MkdirAll(directory, 0o755); err != nil {
		fmt.Fprintf(stderr, "create %q: %v\n", directory, err)
		return exitInvalid
	}

	extracted := 0
	for _, file := range reader.File {
		name := filepath.Clean(file.Name)
		if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			fmt.Fprintf(stderr, "refusing to extract %q outside the target\n", file.Name)
			continue
		}

		target := filepath.Join(directory, name)
		if !strings.HasPrefix(target, filepath.Clean(directory)+string(os.PathSeparator)) {
			fmt.Fprintf(stderr, "refusing to extract %q outside the target\n", file.Name)
			continue
		}

		if file.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}

		source, err := file.Open()
		if err != nil {
			fmt.Fprintf(stderr, "read %q: %v\n", file.Name, err)
			continue
		}

		content, err := io.ReadAll(io.LimitReader(source, 256<<20))
		_ = source.Close()
		if err != nil {
			fmt.Fprintf(stderr, "read %q: %v\n", file.Name, err)
			continue
		}

		if err := os.WriteFile(target, content, 0o644); err != nil {
			fmt.Fprintf(stderr, "write %q: %v\n", target, err)
			continue
		}
		extracted++
		fmt.Fprintf(stdout, "  %s\n", name)
	}

	fmt.Fprintf(stdout, "extracted %d file(s) to %s\n", extracted, directory)
	return exitOK
}
