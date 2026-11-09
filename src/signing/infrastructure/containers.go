package infrastructure

import (
	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/asic"
)

// AsicContainers writes ASiC containers (ETSI EN 319 162-1).
type AsicContainers struct{}

// WriteContainer packs the entries under the container's media type.
func (AsicContainers) WriteContainer(container domain.Container, entries []application.ContainerEntry) ([]byte, error) {
	files := make([]asic.Entry, 0, len(entries))
	for _, entry := range entries {
		files = append(files, asic.Entry{Name: entry.Name, Content: entry.Content})
	}
	return asic.Write(container.MediaType(), files)
}

var _ application.ContainerWriter = AsicContainers{}
