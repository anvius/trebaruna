package infrastructure

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	ledger "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// maximumDownload bounds data fetched for a page: 64 MiB.
const maximumDownload = 64 << 20

// WebData downloads the data a page pointed at, through the connection
// record, after the person approved the address.
type WebData struct{}

// Fetch downloads with GET.
func (WebData) Fetch(ctx context.Context, url string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := ledger.Client(transparency.PurposeWebDelivery, 60*time.Second).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("the site answered HTTP %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, maximumDownload))
}

// LocalFiles writes what save and signandsave produce.
type LocalFiles struct{}

// Write writes the file where the person chose.
func (LocalFiles) Write(path string, content []byte) error { return os.WriteFile(path, content, 0o644) }

// compile-time checks.
var (
	_ application.DataFetcher = WebData{}
	_ application.FileWriter  = LocalFiles{}
)
