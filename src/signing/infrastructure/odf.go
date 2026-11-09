package infrastructure

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// OpenDocument's signature file and namespace (OASIS ODF 1.2, Part 3).
const (
	odfSignaturesEntry     = "META-INF/documentsignatures.xml"
	odfSignaturesNamespace = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0"
	odfMediaTypePrefix     = "application/vnd.oasis.opendocument."
	odfEntryLimit          = 512 << 20
)

// ErrNotOpenDocument means bytes that are not an OpenDocument package.
var ErrNotOpenDocument = errors.New("not an OpenDocument package")

// OdfSigner signs an OpenDocument file inside itself, as LibreOffice does:
// one XAdES signature with a reference to every stream of the package but
// the signatures file (mimetype and the manifest included), added to
// META-INF/documentsignatures.xml beside any earlier signature. The package
// is otherwise copied byte for byte.
type OdfSigner struct {
	xades *XadesSigner
}

// NewOdfSigner builds the adapter over the XML signer.
func NewOdfSigner(xades *XadesSigner) *OdfSigner {
	return &OdfSigner{xades: xades}
}

// SignOdf signs the package in request.Content.
func (s *OdfSigner) SignOdf(ctx context.Context, request application.XadesRequest) ([]byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(request.Content), int64(len(request.Content)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotOpenDocument, err)
	}
	if len(archive.File) == 0 || archive.File[0].Name != "mimetype" {
		return nil, fmt.Errorf("%w: no mimetype first", ErrNotOpenDocument)
	}
	mediaType, err := readZipEntry(archive.File[0], 256)
	if err != nil || !strings.HasPrefix(string(mediaType), odfMediaTypePrefix) {
		return nil, fmt.Errorf("%w: mimetype %q", ErrNotOpenDocument, mediaType)
	}

	streams, holder, err := odfStreams(archive)
	if err != nil {
		return nil, err
	}
	if len(streams) == 0 {
		return nil, fmt.Errorf("the package has nothing to sign")
	}
	if holder == nil {
		holder = []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
			`<document-signatures xmlns="` + odfSignaturesNamespace + `" version="1.2"></document-signatures>`)
	}

	signing := request
	signing.Packaging = domain.XMLDetached
	signing.Content, signing.DocumentName, signing.DocumentCanonical = streams[0].Content, streams[0].Name, streams[0].Canonical
	signing.MoreDocuments = streams[1:]
	signing.Holder = holder
	signatures, err := s.xades.SignXades(ctx, signing)
	if err != nil {
		return nil, err
	}
	return rewritePackage(archive, signatures)
}

// odfStreams reads every stream to sign and the current signatures file.
// A stream is canonicalised when the manifest calls it text/xml, or, when
// the manifest does not list it, when its name ends in .xml: LibreOffice's
// rule (DocumentSignatureManager::isXML).
func odfStreams(archive *zip.Reader) ([]application.DetachedDocument, []byte, error) {
	mediaTypes := map[string]string{}
	var streams []application.DetachedDocument
	var holder []byte
	for _, entry := range archive.File {
		// mimetype is signed too: LibreOffice lists it among the streams a
		// signature must cover, and calls a signature without it partial.
		if entry.FileInfo().IsDir() {
			continue
		}
		content, err := readZipEntry(entry, odfEntryLimit)
		if err != nil {
			return nil, nil, err
		}
		switch entry.Name {
		case odfSignaturesEntry:
			holder = content
			continue
		case "META-INF/manifest.xml":
			mediaTypes = manifestMediaTypes(content)
		}
		streams = append(streams, application.DetachedDocument{Name: entry.Name, Content: content})
	}
	for index := range streams {
		mediaType, listed := mediaTypes[streams[index].Name]
		streams[index].Canonical = mediaType == "text/xml" || (!listed && strings.EqualFold(path.Ext(streams[index].Name), ".xml"))
	}
	return streams, holder, nil
}

// manifestMediaTypes reads the media type of each file the manifest lists.
func manifestMediaTypes(manifest []byte) map[string]string {
	types := map[string]string{}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(manifest); err != nil || document.Root() == nil {
		return types
	}
	for _, entry := range document.Root().ChildElements() {
		if entry.Tag != "file-entry" {
			continue
		}
		types[entry.SelectAttrValue("manifest:full-path", entry.SelectAttrValue("full-path", ""))] =
			entry.SelectAttrValue("manifest:media-type", entry.SelectAttrValue("media-type", ""))
	}
	return types
}

// rewritePackage copies every entry as it was, mimetype first and stored,
// with the signatures file replaced or added.
func rewritePackage(archive *zip.Reader, signatures []byte) ([]byte, error) {
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	written := false
	for _, entry := range archive.File {
		if entry.Name == odfSignaturesEntry {
			if err := writeDeflated(writer, odfSignaturesEntry, signatures); err != nil {
				return nil, err
			}
			written = true
			continue
		}
		if err := writer.Copy(entry); err != nil {
			return nil, err
		}
	}
	if !written {
		if err := writeDeflated(writer, odfSignaturesEntry, signatures); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeDeflated(writer *zip.Writer, name string, content []byte) error {
	// A dated entry: a zero MS-DOS date (month 0) is no date at all.
	entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
	if err != nil {
		return err
	}
	_, err = entry.Write(content)
	return err
}

// readZipEntry reads an entry whole, refusing one larger than limit.
func readZipEntry(entry *zip.File, limit int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", entry.Name, err)
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", entry.Name, err)
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", entry.Name, limit)
	}
	return content, nil
}

var _ application.OdfSigner = (*OdfSigner)(nil)
