package cli

// ASiC containers: a ZIP holding the document plus its signature.
//
// Two container flavours exist (ASiC-S and ASiC-E) because some
// public administrations in Italy accept only that wrapper, and because a
// container keeps the signed file and its signature together, which avoids the
// classic "I sent the PDF but forgot the .p7m".
//
// ASiC-S holds one document and one signature (mimetype application/vnd.etsi.asic-s+zip).
// ASiC-E holds several (mimetype application/vnd.etsi.asic-e+zip).
//
// The container is a plain ZIP with the mimetype as the FIRST entry, stored
// without compression, which is what readers key on.

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ASiC mimetypes, as fixed by ETSI EN 319 162-1.
const (
	asicSMimeType = "application/vnd.etsi.asic-s+zip"
	asicEMimeType = "application/vnd.etsi.asic-e+zip"
)

// runAsic implements `pignus asic <document> <signature>`.
func runAsic(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("asic", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		output  = flags.String("out", "", "output .asice file (default: <document>.asice)")
		kind    = flags.String("type", "asice", "container type: asice (several files) or asics (one)")
		extract = flags.String("extract", "", "extract this container to a directory instead of building one")
	)

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: pignus asic <document> <signature> [-out file.asice]")
		fmt.Fprintln(stderr, "       pignus asic -extract container.asice -out directory")
		flags.PrintDefaults()
	}

	// Flags may come after the positional arguments, which Go's flag package
	// does not support: split them first so `asic a.pdf b.p7m --out x` works.
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

	document, signature := positional[0], positional[1]
	destination := *output
	if destination == "" {
		destination = document + ".asice"
	}

	mimeType := asicEMimeType
	if *kind == "asics" {
		mimeType = asicSMimeType
	}

	if err := buildAsic(destination, mimeType, document, signature); err != nil {
		fmt.Fprintf(stderr, "cannot build the container: %v\n", err)
		return exitInvalid
	}

	fmt.Fprintf(stdout, "built %s\n", destination)
	fmt.Fprintf(stdout, "  mimetype  %s\n", mimeType)
	fmt.Fprintf(stdout, "  document  %s\n", filepath.Base(document))
	fmt.Fprintf(stdout, "  signature %s\n", filepath.Base(signature))
	return exitOK
}

// buildAsic writes the ZIP with the mimetype stored first and uncompressed.
func buildAsic(destination, mimeType string, files ...string) error {
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".asic-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	archive := zip.NewWriter(temporary)

	// The mimetype entry must be stored, not deflated: every reader checks it
	// by reading the first bytes of the file, not by inflating it.
	header := &zip.FileHeader{Name: "mimetype", Method: zip.Store}
	entry, err := archive.CreateHeader(header)
	if err != nil {
		return err
	}
	if _, err := entry.Write([]byte(mimeType)); err != nil {
		return err
	}

	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %q: %w", path, err)
		}

		// Inside an ASiC container documents live under the root; signatures too.
		name := filepath.Base(path)
		writer, err := archive.Create(name)
		if err != nil {
			return err
		}
		if _, err := writer.Write(content); err != nil {
			return err
		}
	}

	if err := archive.Close(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, destination)
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
