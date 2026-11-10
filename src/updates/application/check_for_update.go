// Package application holds the update check: is a release newer than the
// running program published?
package application

import (
	"context"
	"errors"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/updates/domain"
)

// ErrNoReleases means the source published no release trebaruna can read.
var ErrNoReleases = errors.New("no published release was found")

// ReleaseSource lists the published releases.
type ReleaseSource interface {
	Releases(ctx context.Context) ([]domain.Release, error)
}

// UpdateVerdict is what the check found: the running version, the newest
// published release, and whether that release is newer.
type UpdateVerdict struct {
	Running domain.Version
	Latest  domain.Release
	Newer   bool
}

// CheckForUpdate compares the running version with the newest release the
// source publishes. It only reads: nothing is downloaded or installed.
type CheckForUpdate struct {
	source ReleaseSource
}

// NewCheckForUpdate wires the use case.
func NewCheckForUpdate(source ReleaseSource) *CheckForUpdate {
	return &CheckForUpdate{source: source}
}

// Execute checks; running is the version the program reports.
func (u *CheckForUpdate) Execute(ctx context.Context, running string) (UpdateVerdict, error) {
	current, err := domain.ParseVersion(running)
	if err != nil || current.Unknown() {
		return UpdateVerdict{}, fmt.Errorf("this build does not know its version (%s), so it cannot tell a newer one", running)
	}
	releases, err := u.source.Releases(ctx)
	if err != nil {
		return UpdateVerdict{}, err
	}
	if len(releases) == 0 {
		return UpdateVerdict{}, ErrNoReleases
	}
	latest := releases[0]
	for _, release := range releases[1:] {
		if release.Version.Newer(latest.Version) {
			latest = release
		}
	}
	return UpdateVerdict{Running: current, Latest: latest, Newer: latest.Version.Newer(current)}, nil
}
