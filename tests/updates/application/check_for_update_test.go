package application_test

// The update check compares the running version with the newest release
// published, whatever order the source lists them in.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/updates/application"
	"codeberg.org/simplicer/trebaruna/src/updates/domain"
)

type fakeSource struct {
	releases []domain.Release
	err      error
	asked    int
}

func (f *fakeSource) Releases(context.Context) ([]domain.Release, error) {
	f.asked++
	return f.releases, f.err
}

func release(t *testing.T, text string) domain.Release {
	t.Helper()
	parsed, err := domain.ParseVersion(text)
	if err != nil {
		t.Fatal(err)
	}
	return domain.Release{Version: parsed, Page: "https://example.org/" + text}
}

func TestTheNewestPublishedReleaseIsCompared(t *testing.T) {
	source := &fakeSource{releases: []domain.Release{release(t, "0.20.5-unstable"), release(t, "0.106.0-unstable"), release(t, "0.20.3-unstable")}}
	check := application.NewCheckForUpdate(source)
	for running, newer := range map[string]bool{"0.105.0-unstable": true, "0.106.0-unstable": false, "0.107.1-unstable": false} {
		verdict, err := check.Execute(context.Background(), running)
		if err != nil || verdict.Newer != newer || verdict.Latest.Version.String() != "0.106.0-unstable" ||
			verdict.Latest.Page != "https://example.org/0.106.0-unstable" || verdict.Running.String() != running {
			t.Errorf("running %s: %+v %v", running, verdict, err)
		}
	}
}

func TestAnUpdateCheckSaysWhatItCannotTell(t *testing.T) {
	source := &fakeSource{}
	for _, running := range []string{"0.0.0-dev", "unknown"} {
		if _, err := application.NewCheckForUpdate(source).Execute(context.Background(), running); err == nil ||
			!strings.Contains(err.Error(), "does not know its version") {
			t.Errorf("%s: %v", running, err)
		}
	}
	if source.asked != 0 {
		t.Errorf("the source was asked %d times for a build that does not know its version", source.asked)
	}
	if _, err := application.NewCheckForUpdate(source).Execute(context.Background(), "1.0.0"); !errors.Is(err, application.ErrNoReleases) {
		t.Errorf("no release: %v", err)
	}
	source.err = errors.New("offline")
	if _, err := application.NewCheckForUpdate(source).Execute(context.Background(), "1.0.0"); err == nil || err.Error() != "offline" {
		t.Errorf("a source that fails: %v", err)
	}
}
