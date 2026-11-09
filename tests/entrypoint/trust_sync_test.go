package cli_test

import (
	"strings"
	"testing"
)

// TestTheEUListIsFetchedOnlyOverHTTPS: the list of the lists is
// authenticated by its signature, and fetched over HTTPS, or HTTP on this
// computer for tests; anything else is refused before any connection.
func TestTheEUListIsFetchedOnlyOverHTTPS(t *testing.T) {
	for _, address := range []string{"http://ec.europa.eu/tools/lotl/eu-lotl.xml", "ftp://example.org/lotl.xml", "eu-lotl.xml"} {
		_, stderr, code := run("trust", "sync", "--territory", "ES", "--dir", t.TempDir(), "--lotl", address)
		if code != 2 || !strings.Contains(stderr, "https") {
			t.Errorf("%s: exit %d, %s", address, code, stderr)
		}
	}
}
