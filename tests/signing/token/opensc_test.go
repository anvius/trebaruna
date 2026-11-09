package infrastructure_test

import (
	"slices"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// TestOpenSCIsLookedForWhereEachSystemInstallsIt: the person should not need to
// know the path of the free driver; the places each system puts it are tried.
func TestOpenSCIsLookedForWhereEachSystemInstallsIt(t *testing.T) {
	cases := []struct {
		system, architecture, expected string
	}{
		{"linux", "amd64", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"},
		{"linux", "arm64", "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so"},
		{"linux", "amd64", "/usr/lib64/opensc-pkcs11.so"},
		{"linux", "amd64", "/usr/lib/opensc-pkcs11.so"},
		// The Flatpak carries its own: the runtime has none.
		{"linux", "amd64", "/app/lib/opensc-pkcs11.so"},
		{"freebsd", "amd64", "/usr/local/lib/opensc-pkcs11.so"},
		{"darwin", "arm64", "/Library/OpenSC/lib/opensc-pkcs11.so"},
		{"darwin", "arm64", "/opt/homebrew/lib/opensc-pkcs11.so"},
		{"windows", "amd64", `C:\Windows\System32\opensc-pkcs11.dll`},
	}
	for _, entry := range cases {
		locations := infrastructure.OpenSCLocations(entry.system, entry.architecture)
		if !slices.Contains(locations, entry.expected) {
			t.Errorf("%s/%s: %s is not tried (%v)", entry.system, entry.architecture, entry.expected, locations)
		}
	}

	for _, location := range infrastructure.OpenSCLocations("linux", "arm64") {
		if strings.Contains(location, "x86_64") {
			t.Errorf("an arm64 system must not try %s", location)
		}
	}
	// The system's own OpenSC comes before the Flatpak's place.
	linux := infrastructure.OpenSCLocations("linux", "amd64")
	if linux[len(linux)-1] != "/app/lib/opensc-pkcs11.so" {
		t.Errorf("/app/lib is tried last: %v", linux)
	}
}

// TestOpenSCModuleIsAnInstalledFile: what is found exists; what is not found
// is the empty string, never a guess.
func TestOpenSCModuleIsAnInstalledFile(t *testing.T) {
	module := infrastructure.OpenSCModule()
	if module == "" {
		t.Skip("OpenSC is not installed here")
	}
	if !strings.Contains(module, "opensc-pkcs11") {
		t.Errorf("found %s, which is not the OpenSC module", module)
	}
}
