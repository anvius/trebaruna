package domain_test

// Versions as trebaruna numbers them, ordered as Semantic Versioning says
// (semver.org, 11).

import (
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/updates/domain"
)

func version(t *testing.T, text string) domain.Version {
	t.Helper()
	parsed, err := domain.ParseVersion(text)
	if err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return parsed
}

func TestVersionsAreOrderedAsSemanticVersioningSays(t *testing.T) {
	ascending := []string{"0.20.3-unstable", "0.20.5-unstable", "0.105.0-unstable", "1.0.0-rc.1", "1.0.0-rc.2", "1.0.0-rc.10",
		"1.0.0", "1.0.1", "1.1.0", "2.0.0-alpha", "2.0.0-alpha.1", "2.0.0-alpha.beta", "2.0.0-beta", "2.0.0"}
	for index := 1; index < len(ascending); index++ {
		older, newer := version(t, ascending[index-1]), version(t, ascending[index])
		if !newer.Newer(older) || older.Newer(newer) {
			t.Errorf("%s must come after %s", newer, older)
		}
	}
	if same := version(t, "v0.105.0-unstable"); same.Newer(version(t, "0.105.0-unstable")) || same.String() != "0.105.0-unstable" {
		t.Errorf("a tag and its version are the same: %s", same)
	}
}

func TestOnlyAVersionIsAVersion(t *testing.T) {
	for _, text := range []string{"", "1.0", "1.0.0.0", "v1.x.0", "1.01.0", "1.0.0-", "-1.0.0", "latest"} {
		if _, err := domain.ParseVersion(text); !errors.Is(err, domain.ErrNotAVersion) {
			t.Errorf("%q: %v", text, err)
		}
	}
}
