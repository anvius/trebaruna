// Package application orchestrates trust list retrieval and authentication.
package application

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	// LOTLAnchors are the certificates the Official Journal announced for
	// signing the EU list of the lists, and AnchorAnnouncement the address
	// of that notice as the list names it: the list is used only when one
	// of them signed it whole, or a chain of pivot lists leads from them to
	// its signer.
	LOTLAnchors        []*x509.Certificate
	AnchorAnnouncement string
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
			_ = writeInto(u.QuarantineDir, entry.Territory+"-rejected.xml", content)
		}
		return result, nil
	}

	// The file is named by the code the authenticated EU list publishes,
	// which the parser accepts only as two capital letters.
	if err := writeInto(u.CacheDir, entry.Territory+".xml", content); err != nil {
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
	if err := u.authenticateLOTL(content, lotl); err != nil {
		return domain.LOTL{}, err
	}
	u.fetched = &lotl
	return lotl, nil
}

// authenticateLOTL accepts the EU list of the lists only when its own
// signature, covering it whole, was made with a certificate the Official
// Journal announced, or with one a chain of pivot lists announced after
// that notice (ETSI TS 119 615): each pivot signed with a certificate of
// the set before it, naming the next set in its pointer to itself. TLS to
// the Commission's site is not what makes the list trusted.
func (u *SyncTerritory) authenticateLOTL(content []byte, lotl domain.LOTL) error {
	if len(u.LOTLAnchors) == 0 {
		return fmt.Errorf("no anchors for the EU list of the lists: it cannot be authenticated")
	}
	if trustinfrastructure.InspectListSignatureWithAnchors(content, u.LOTLAnchors).Trusted {
		return nil
	}
	announced := slices.Index(lotl.Announcements, u.AnchorAnnouncement)
	if announced < 0 {
		return fmt.Errorf("the EU list of the lists is not signed with the certificates of the notice trebaruna knows (%s) "+
			"and no longer names it: a newer trebaruna carries the notice that replaced it", u.AnchorAnnouncement)
	}
	// The pivots named before the notice came after it; the list names
	// them newest first.
	var pivots []string
	for _, address := range lotl.Announcements[:announced] {
		if strings.HasSuffix(strings.ToLower(address), ".xml") {
			pivots = append(pivots, address)
		}
	}
	slices.Reverse(pivots)
	signers := u.LOTLAnchors
	for _, address := range pivots {
		pivot, err := u.Lists.Fetch(address)
		if err != nil {
			return fmt.Errorf("fetch the pivot list %s: %w", address, err)
		}
		if !trustinfrastructure.InspectListSignatureWithAnchors(pivot, signers).Trusted {
			return fmt.Errorf("the pivot list %s is not signed with a certificate announced before it", address)
		}
		parsed, err := trustinfrastructure.LOTLParser{}.Parse(bytes.NewReader(pivot))
		if err != nil || len(parsed.Signers) == 0 {
			return fmt.Errorf("the pivot list %s names no certificates to sign with", address)
		}
		signers = parsed.Signers
	}
	if !trustinfrastructure.InspectListSignatureWithAnchors(content, signers).Trusted {
		return fmt.Errorf("the EU list of the lists is not signed whole with a certificate the Official Journal or its pivots announced")
	}
	return nil
}

// writeInto writes content into a directory, creating it if needed.
func writeInto(directory, name string, content []byte) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, name), content, 0o644)
}
