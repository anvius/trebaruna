package infrastructure

import (
	"fmt"
	"net/url"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/asic"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// AsicContainers writes ASiC containers (ETSI EN 319 162-1).
type AsicContainers struct{}

// WriteContainer packs the entries under the container's media type.
func (AsicContainers) WriteContainer(container domain.Container, entries []application.ContainerEntry) ([]byte, error) {
	return asic.Write(container.MediaType(), asicEntries(entries))
}

// Manifest writes the ASiCManifest an ASiC-E's CAdES signature covers.
func (AsicContainers) Manifest(signatureEntry string, documents []application.ContainerEntry) ([]byte, error) {
	return asic.Manifest(signatureEntry, asicEntries(documents))
}

// ManifestOf is the ASiCManifest whose SigReference names the signature.
func (AsicContainers) ManifestOf(signatureEntry string, entries []application.ContainerEntry) (application.ContainerEntry, bool) {
	manifest, found := asic.ManifestOf(signatureEntry, asicEntries(entries))
	return application.ContainerEntry{Name: manifest.Name, Content: manifest.Content}, found
}

// maxContainerEntry bounds a file read from a container.
const maxContainerEntry = 512 << 20

// ReadContainer opens an ASiC container.
func (AsicContainers) ReadContainer(content []byte) (domain.Container, []application.ContainerEntry, error) {
	mediaType, files, err := asic.Read(content, maxContainerEntry)
	if err != nil {
		return "", nil, err
	}
	var container domain.Container
	switch mediaType {
	case domain.ASiCS.MediaType():
		container = domain.ASiCS
	case domain.ASiCE.MediaType():
		container = domain.ASiCE
	default:
		return "", nil, fmt.Errorf("the container is not ASiC (its media type is %q)", mediaType)
	}
	entries := make([]application.ContainerEntry, 0, len(files))
	for _, file := range files {
		entries = append(entries, application.ContainerEntry{Name: file.Name, Content: file.Content})
	}
	return container, entries, nil
}

// AddXMLSignatures moves the ds:Signature elements of added into the root
// of signatures (both asic:XAdESSignatures). The signatures that verified
// before, with the certificate they carry and the container's files, must
// verify after, and the added ones too: a root declaring other namespaces
// changes an inclusive canonical form.
func (AsicContainers) AddXMLSignatures(signatures, added []byte, files []application.ContainerEntry) ([]byte, error) {
	existing, err := parseDocument(signatures)
	if err != nil {
		return nil, err
	}
	addition, err := parseDocument(added)
	if err != nil {
		return nil, err
	}
	resolve := func(uri string) ([]byte, error) {
		name, _ := url.PathUnescape(uri)
		for _, file := range files {
			if file.Name == name {
				return file.Content, nil
			}
		}
		return nil, fmt.Errorf("%w: %s", xmldsig.ErrContentMissing, uri)
	}
	before := holdingSignaturesResolved(existing, resolve)
	var addedValues []string
	for _, signature := range xmldsig.Signatures(addition) {
		if value := signature.SelectElement("SignatureValue"); value != nil {
			addedValues = append(addedValues, strings.Join(strings.Fields(value.Text()), ""))
		}
		existing.Root().AddChild(signature.Copy())
	}
	merged, err := existing.WriteToBytes()
	if err != nil {
		return nil, err
	}
	reread, err := parseDocument(merged)
	if err != nil {
		return nil, err
	}
	after := holdingSignaturesResolved(reread, resolve)
	for value := range before {
		if !after[value] {
			return nil, fmt.Errorf("adding the signature to the container's signatures file would break another")
		}
	}
	for _, value := range addedValues {
		if !after[value] {
			return nil, fmt.Errorf("the signatures file of the container does not keep the new signature valid")
		}
	}
	return merged, nil
}

// asicEntries converts the use case's entries for the writer.
func asicEntries(entries []application.ContainerEntry) []asic.Entry {
	files := make([]asic.Entry, 0, len(entries))
	for _, entry := range entries {
		files = append(files, asic.Entry{Name: entry.Name, Content: entry.Content})
	}
	return files
}

var _ application.ContainerWriter = AsicContainers{}
