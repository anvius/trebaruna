// Package asic writes ASiC containers (ETSI EN 319 162-1): a ZIP whose
// first entry, stored uncompressed, is its media type, so a reader knows it
// from the first bytes; then the documents at the root and the signatures
// under META-INF.
package asic

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// Manifest writes the ASiCManifest a CAdES signature of an ASiC-E container
// covers (ETSI EN 319 162-1, A.4): the signature it belongs to, then each
// document with its media type and SHA-256 digest. The signature over the
// manifest proves the documents through those digests.
func Manifest(signatureEntry string, documents []Entry) ([]byte, error) {
	var manifest strings.Builder
	manifest.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="no"?>` + "\n")
	manifest.WriteString(`<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`)
	manifest.WriteString(`<asic:SigReference URI="` + attribute(escapePath(signatureEntry)) + `" MimeType="application/pkcs7-signature"/>`)
	for _, document := range documents {
		if document.Name == "" {
			return nil, fmt.Errorf("a document of the manifest has no name")
		}
		digest := sha256.Sum256(document.Content)
		manifest.WriteString(`<asic:DataObjectReference URI="` + attribute(escapePath(document.Name)) +
			`" MimeType="` + attribute(mediaType(document.Content)) + `">` +
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
			`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</ds:DigestValue>` +
			`</asic:DataObjectReference>`)
	}
	manifest.WriteString(`</asic:ASiCManifest>`)
	return []byte(manifest.String()), nil
}

// escapePath escapes each segment of a path in the container, keeping the
// slashes between them.
func escapePath(name string) string {
	segments := strings.Split(name, "/")
	for index, segment := range segments {
		segments[index] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

// mediaType sniffs a document's media type, without parameters.
func mediaType(content []byte) string {
	detected := http.DetectContentType(content)
	if semicolon := strings.Index(detected, ";"); semicolon >= 0 {
		detected = detected[:semicolon]
	}
	return strings.TrimSpace(detected)
}

// attribute escapes text for an attribute value.
func attribute(text string) string {
	var escaped strings.Builder
	_ = xml.EscapeText(&escaped, []byte(text))
	return strings.ReplaceAll(escaped.String(), `"`, "&quot;")
}

// Read opens a container: its media type (the mimetype entry) and its other
// files, in their order. Names that would leave the container are refused,
// and no file may exceed limit bytes.
func Read(container []byte, limit int64) (string, []Entry, error) {
	archive, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return "", nil, fmt.Errorf("not a container: %w", err)
	}
	mediaType := ""
	var entries []Entry
	for _, file := range archive.File {
		if file.FileInfo().IsDir() {
			continue
		}
		cleaned := path.Clean(file.Name)
		if cleaned != file.Name || path.IsAbs(cleaned) || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, `\`) {
			return "", nil, fmt.Errorf("%q cannot be a file of the container", file.Name)
		}
		if file.UncompressedSize64 > uint64(limit) {
			return "", nil, fmt.Errorf("%q is larger than %d bytes", file.Name, limit)
		}
		reader, err := file.Open()
		if err != nil {
			return "", nil, err
		}
		content, err := io.ReadAll(io.LimitReader(reader, limit+1))
		reader.Close()
		if err != nil {
			return "", nil, err
		}
		if int64(len(content)) > limit {
			return "", nil, fmt.Errorf("%q is larger than %d bytes", file.Name, limit)
		}
		if file.Name == "mimetype" {
			mediaType = strings.TrimSpace(string(content))
			continue
		}
		entries = append(entries, Entry{Name: file.Name, Content: content})
	}
	return mediaType, entries, nil
}
