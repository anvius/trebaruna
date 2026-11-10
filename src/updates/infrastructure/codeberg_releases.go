// Package infrastructure reads the releases trebaruna publishes.
package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/updates/application"
	"codeberg.org/simplicer/trebaruna/src/updates/domain"
)

// ProjectRepository is where trebaruna is published.
const ProjectRepository = "https://codeberg.org/simplicer/trebaruna"

// CodebergReleases lists the release tags of a Codeberg (Forgejo)
// repository, through its public API, with the recording client: the
// request is listed among the program's connections as an update check.
type CodebergReleases struct {
	// Repository is the repository's address; empty is trebaruna's.
	Repository string
}

// tagsPerPage is how many tags one request reads; the newest are first.
const tagsPerPage = 50

// Releases reads the tags that name a version, each with its page.
func (c CodebergReleases) Releases(ctx context.Context) ([]domain.Release, error) {
	repository := strings.TrimSuffix(c.Repository, "/")
	if repository == "" {
		repository = ProjectRepository
	}
	parsed, err := url.Parse(repository)
	if err != nil {
		return nil, err
	}
	api := *parsed
	api.Path = "/api/v1/repos" + parsed.Path + "/tags"
	api.RawQuery = fmt.Sprintf("limit=%d", tagsPerPage)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, api.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := transparency.Client(transparencydomain.PurposeUpdateCheck, 15*time.Second).Do(request)
	if err != nil {
		return nil, fmt.Errorf("ask %s for its releases: %w", parsed.Host, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s when asked for its releases", parsed.Host, response.Status)
	}
	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&tags); err != nil {
		return nil, fmt.Errorf("read %s's releases: %w", parsed.Host, err)
	}
	var releases []domain.Release
	for _, tag := range tags {
		version, err := domain.ParseVersion(tag.Name)
		if err != nil || !strings.HasPrefix(tag.Name, "v") {
			continue
		}
		releases = append(releases, domain.Release{Version: version, Page: repository + "/releases/tag/" + url.PathEscape(tag.Name)})
	}
	return releases, nil
}

// compile-time proof that the adapter satisfies the port.
var _ application.ReleaseSource = CodebergReleases{}
