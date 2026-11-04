package cli_test

import (
	"archive/zip"
	"os"
)

// writeEvilZip creates a container whose member tries to escape the extraction
// directory. It is a test fixture, not a vulnerability.
func writeEvilZip(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	archive := zip.NewWriter(file)

	entry, err := archive.Create("mimetype")
	if err != nil {
		return err
	}
	if _, err := entry.Write([]byte("application/vnd.etsi.asic-e+zip")); err != nil {
		return err
	}

	escaping, err := archive.Create("../../escaped.txt")
	if err != nil {
		return err
	}
	if _, err := escaping.Write([]byte("pwned")); err != nil {
		return err
	}

	return archive.Close()
}
