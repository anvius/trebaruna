// Package asic writes ASiC containers (ETSI EN 319 162-1): a ZIP whose
// first entry, stored uncompressed, is its media type, so a reader knows it
// from the first bytes; then the documents at the root and the signatures
// under META-INF.
package asic

import (
	"archive/zip"
	"bytes"
	"fmt"
	"path"
	"strings"
)

// Entry is a file of the container, by its path inside it.
type Entry struct {
	Name    string
	Content []byte
}

// Write builds the container. Names must be relative paths that stay inside
// it; the ZIP comment repeats the media type, as AutoFirma writes it.
func Write(mediaType string, entries []Entry) ([]byte, error) {
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	if err := archive.SetComment("mimetype=" + mediaType); err != nil {
		return nil, err
	}
	header := &zip.FileHeader{Name: "mimetype", Method: zip.Store}
	writer, err := archive.CreateHeader(header)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write([]byte(mediaType)); err != nil {
		return nil, err
	}

	seen := map[string]bool{"mimetype": true}
	for _, entry := range entries {
		cleaned := path.Clean(entry.Name)
		if entry.Name == "" || cleaned != entry.Name || path.IsAbs(cleaned) || cleaned == ".." ||
			strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, `\`) {
			return nil, fmt.Errorf("%q cannot be a file of the container", entry.Name)
		}
		if seen[entry.Name] {
			return nil, fmt.Errorf("the container would hold %q twice", entry.Name)
		}
		seen[entry.Name] = true
		writer, err := archive.CreateHeader(&zip.FileHeader{Name: entry.Name, Method: zip.Deflate})
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(entry.Content); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
