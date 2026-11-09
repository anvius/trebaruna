package infrastructure

import (
	"fmt"
	"io"
	"net/http"
	"time"

	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// maxListSize bounds a downloaded list; the largest national lists are a few MB.
const maxListSize = 32 << 20

// WebLOTL downloads the EU list of the lists. The connection is recorded as a
// trust-list download, like every other request the program makes.
type WebLOTL struct {
	URL string
}

// Fetch downloads the list.
func (w WebLOTL) Fetch() ([]byte, error) {
	return download(transparency.Client(transparencydomain.PurposeTrustList, 2*time.Minute), w.URL)
}

// WebList downloads one national list.
type WebList struct{}

// Fetch downloads the list.
func (WebList) Fetch(url string) ([]byte, error) {
	return download(transparency.Client(transparencydomain.PurposeTrustList, 3*time.Minute), url)
}

func download(client *http.Client, url string) ([]byte, error) {
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, maxListSize))
}
