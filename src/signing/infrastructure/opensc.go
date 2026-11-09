package infrastructure

import (
	"os"
	"runtime"
)

// OpenSCModule returns the OpenSC PKCS#11 module installed on this system, or
// the empty string when none is found.
//
// OpenSC is the free driver for the national and qualified signature cards, so
// it is what a card uses unless the person picks a vendor module (SPECS,
// principle 2). Looking in the places each system installs it spares them from
// knowing the path.
func OpenSCModule() string {
	for _, location := range OpenSCLocations(runtime.GOOS, runtime.GOARCH) {
		if info, err := os.Stat(location); err == nil && !info.IsDir() {
			return location
		}
	}
	return ""
}

// OpenSCLocations lists where OpenSC installs its PKCS#11 module on a system
// and architecture, in the order they are tried.
func OpenSCLocations(system, architecture string) []string {
	switch system {
	case "windows":
		return []string{
			`C:\Windows\System32\opensc-pkcs11.dll`,
			`C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll`,
		}
	case "darwin":
		return []string{
			"/Library/OpenSC/lib/opensc-pkcs11.so",
			"/opt/homebrew/lib/opensc-pkcs11.so",
			"/usr/local/lib/opensc-pkcs11.so",
		}
	}

	var locations []string
	if triplet, known := debianTriplets[architecture]; known {
		locations = append(locations,
			"/usr/lib/"+triplet+"/opensc-pkcs11.so",
			"/usr/lib/"+triplet+"/pkcs11/opensc-pkcs11.so")
	}
	return append(locations,
		"/usr/lib64/opensc-pkcs11.so",
		"/usr/lib64/pkcs11/opensc-pkcs11.so",
		"/usr/lib/opensc-pkcs11.so",
		"/usr/lib/pkcs11/opensc-pkcs11.so",
		"/usr/local/lib/opensc-pkcs11.so")
}

// debianTriplets maps Go architectures onto the multiarch directories of
// Debian and Ubuntu.
var debianTriplets = map[string]string{
	"amd64":   "x86_64-linux-gnu",
	"arm64":   "aarch64-linux-gnu",
	"386":     "i386-linux-gnu",
	"arm":     "arm-linux-gnueabihf",
	"riscv64": "riscv64-linux-gnu",
	"ppc64le": "powerpc64le-linux-gnu",
	"s390x":   "s390x-linux-gnu",
}
