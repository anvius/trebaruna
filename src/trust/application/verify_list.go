// Package application orchestrates trust list retrieval and authentication.
package application

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"codeberg.org/anvius/pignus/src/trust/domain"
	trustinfrastructure "codeberg.org/anvius/pignus/src/trust/infrastructure"
)

// LOTLSource fetches the EU list of the lists.
//
// It is the root of the chain: it names every national list and publishes the
// certificates their operators sign with. Without it, a downloaded TSL is a file
// of unknown provenance.
type LOTLSource interface {
	Fetch() ([]byte, error)
}

// ListSource fetches one national list.
type ListSource interface {
	Fetch(url string) ([]byte, error)
}

// SyncTerritory downloads a national list, authenticates it against the LOTL
// anchors, and stores it only if the signature checks out.
//
// The order matters: parse, verify the signature, and only then write to the
// cache that the verifier reads. A list that fails authentication is never
// written where it could be mistaken for a trusted one.
type SyncTerritory struct {
	LOTL  LOTLSource
	Lists ListSource
	// CacheDir is where authenticated lists are stored.
	CacheDir string
	// QuarantineDir keeps rejected downloads for inspection.
	QuarantineDir string
}

// Result describes what happened to one territory.
type Result struct {
	Territory     string
	Location      string
	Authenticated bool
	Written       bool
	Services      int
	Qualified     int
	NextUpdate    time.Time
	Reason        string
}

// Execute syncs one territory.
func (u *SyncTerritory) Execute(territory string) (Result, error) {
	result := Result{Territory: territory}

	lotlContent, err := u.LOTL.Fetch()
	if err != nil {
		return result, fmt.Errorf("fetch the EU list of the lists: %w", err)
	}

	lotl, err := trustinfrastructure.LOTLParser{}.Parse(bytes.NewReader(lotlContent))
	if err != nil {
		return result, err
	}

	entry, found := lotl.Find(territory)
	if !found {
		return result, fmt.Errorf("territory %q does not appear in the EU list of the lists", territory)
	}
	result.Location = entry.Location

	if !entry.XML() {
		result.Reason = "this territory publishes only a PDF; it cannot be parsed or authenticated"
		return result, nil
	}
	if !entry.CanSign() {
		result.Reason = "the EU list publishes no signing certificate for this territory"
		return result, nil
	}

	content, err := u.Lists.Fetch(entry.Location)
	if err != nil {
		return result, fmt.Errorf("fetch %s: %w", entry.Location, err)
	}

	integrity := trustinfrastructure.InspectListSignatureWithAnchors(content, entry.Certificates)
	result.Authenticated = integrity.Trusted
	result.Reason = integrity.Reason

	list, parseErr := trustinfrastructure.TSLParser{}.Parse(bytes.NewReader(content))
	if parseErr != nil {
		return result, fmt.Errorf("parse %s: %w", entry.Location, parseErr)
	}
	result.Services = list.ServiceCount()
	result.Qualified = list.QualifiedCount()
	result.NextUpdate = list.NextUpdate

	if !integrity.Trusted {
		// Keep the rejected file for diagnosis, never in the cache.
		if u.QuarantineDir != "" {
			_ = writeInto(u.QuarantineDir, territory+"-rejected.xml", content)
		}
		return result, nil
	}

	if err := writeInto(u.CacheDir, territory+".xml", content); err != nil {
		return result, err
	}
	result.Written = true
	return result, nil
}

// Territory reports the entry the LOTL publishes for a territory.
func (u *SyncTerritory) Territory(territory string) (domain.LOTLEntry, error) {
	lotlContent, err := u.LOTL.Fetch()
	if err != nil {
		return domain.LOTLEntry{}, fmt.Errorf("fetch the EU list of the lists: %w", err)
	}

	lotl, err := trustinfrastructure.LOTLParser{}.Parse(bytes.NewReader(lotlContent))
	if err != nil {
		return domain.LOTLEntry{}, err
	}

	entry, found := lotl.Find(territory)
	if !found {
		return domain.LOTLEntry{}, fmt.Errorf("territory %q does not appear in the EU list of the lists", territory)
	}
	return entry, nil
}

// HTTPLOTL fetches the EU list over HTTPS.
type HTTPLOTL struct {
	URL    string
	Client *http.Client
}

// Fetch downloads the list.
func (h HTTPLOTL) Fetch() ([]byte, error) {
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	return fetch(client, h.URL)
}

// HTTPList fetches a national list over HTTPS.
type HTTPList struct {
	Client *http.Client
}

// Fetch downloads the list.
func (h HTTPList) Fetch(url string) ([]byte, error) {
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Minute}
	}
	return fetch(client, url)
}

// fetch performs the request with a size limit.
func fetch(client *http.Client, url string) ([]byte, error) {
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 32<<20))
}

// writeInto writes content into a directory, creating it if needed.
func writeInto(directory, name string, content []byte) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, name), content, 0o644)
}
