// Package application orchestrates trust list retrieval and authentication.
package application

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"codeberg.org/simplicer/trebaruna/src/trust/domain"
	trustinfrastructure "codeberg.org/simplicer/trebaruna/src/trust/infrastructure"
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

	// fetched is the EU list of the lists once downloaded: a sync of every
	// territory reads it once, not once per territory.
	fetched *domain.LOTL
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

	entry, err := u.Territory(territory)
	if err != nil {
		return result, err
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
	lotl, err := u.lotl()
	if err != nil {
		return domain.LOTLEntry{}, err
	}
	entry, found := lotl.Find(territory)
	if !found {
		return domain.LOTLEntry{}, fmt.Errorf("territory %q does not appear in the EU list of the lists", territory)
	}
	return entry, nil
}

// Territories are the territories whose lists can be synced: published in
// XML, with a certificate to authenticate them.
func (u *SyncTerritory) Territories() ([]string, error) {
	lotl, err := u.lotl()
	if err != nil {
		return nil, err
	}
	var territories []string
	for _, entry := range lotl.Entries {
		if entry.XML() && entry.CanSign() {
			territories = append(territories, entry.Territory)
		}
	}
	return territories, nil
}

// lotl downloads and parses the EU list of the lists the first time; a
// failed download is tried again next time.
func (u *SyncTerritory) lotl() (domain.LOTL, error) {
	if u.fetched != nil {
		return *u.fetched, nil
	}
	content, err := u.LOTL.Fetch()
	if err != nil {
		return domain.LOTL{}, fmt.Errorf("fetch the EU list of the lists: %w", err)
	}
	lotl, err := trustinfrastructure.LOTLParser{}.Parse(bytes.NewReader(content))
	if err != nil {
		return domain.LOTL{}, err
	}
	u.fetched = &lotl
	return lotl, nil
}

// writeInto writes content into a directory, creating it if needed.
func writeInto(directory, name string, content []byte) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, name), content, 0o644)
}
