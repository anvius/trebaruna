package infrastructure_test

// The releases are the repository's tags that name a version, read through
// the Forgejo API with the recording client, each with its page.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/updates/infrastructure"
)

func TestTheReleasesAreTheTagsThatNameAVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/repos/simplicer/trebaruna/tags" || request.URL.Query().Get("limit") == "" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Write([]byte(`[{"name":"v0.20.5-unstable"},{"name":"nightly"},{"name":"0.30.0"},{"name":"v0.106.0-unstable"}]`))
	}))
	defer server.Close()
	transparency.Reset()

	releases, err := infrastructure.CodebergReleases{Repository: server.URL + "/simplicer/trebaruna"}.Releases(context.Background())
	if err != nil || len(releases) != 2 {
		t.Fatalf("%+v %v", releases, err)
	}
	if releases[1].Version.String() != "0.106.0-unstable" || releases[1].Page != server.URL+"/simplicer/trebaruna/releases/tag/v0.106.0-unstable" {
		t.Errorf("%+v", releases[1])
	}
	recorded := transparency.Connections()
	if len(recorded) != 1 || recorded[0].Purpose != transparencydomain.PurposeUpdateCheck || recorded[0].Method != http.MethodGet {
		t.Errorf("recorded %+v", recorded)
	}

	if _, err := (infrastructure.CodebergReleases{Repository: server.URL + "/another/project"}).Releases(context.Background()); err == nil {
		t.Error("a repository that answers 404 has releases")
	}
}
