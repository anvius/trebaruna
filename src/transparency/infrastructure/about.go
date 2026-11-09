package infrastructure

import (
	"runtime"
	"runtime/debug"
	"sort"
)

// Dependency is one module linked into the binary.
type Dependency struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	// License is the SPDX identifier read from the module's licence file when
	// the table was last regenerated; "unreviewed" means a module the table
	// does not know, which the licence test refuses.
	License string `json:"license"`
}

// Build describes the running binary: what it is, where it came from and what
// it contains. Anyone can rebuild from the revision and compare (ADR-0017).
type Build struct {
	Version   string `json:"version"`
	Go        string `json:"go"`
	Platform  string `json:"platform"`
	Revision  string `json:"revision,omitempty"`
	Modified  bool   `json:"modified"`
	BuiltFrom string `json:"source"`
	License   string `json:"license"`
	// PKCS11 reports whether this build can talk to smartcards and tokens.
	PKCS11       bool         `json:"pkcs11"`
	Dependencies []Dependency `json:"dependencies"`
}

// Describe reads the build information the Go toolchain embedded.
func Describe(version string, pkcs11 bool) Build {
	build := Build{
		Version:   version,
		Go:        runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		BuiltFrom: "https://codeberg.org/simplicer/trebaruna",
		License:   "AGPL-3.0-or-later",
		PKCS11:    pkcs11,
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return build
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			build.Revision = setting.Value
		case "vcs.modified":
			build.Modified = setting.Value == "true"
		}
	}
	for _, module := range info.Deps {
		if module.Replace != nil {
			module = module.Replace
		}
		build.Dependencies = append(build.Dependencies, Dependency{
			Path: module.Path, Version: module.Version, License: LicenseOf(module.Path),
		})
	}
	sort.Slice(build.Dependencies, func(i, j int) bool { return build.Dependencies[i].Path < build.Dependencies[j].Path })
	return build
}

// LicenseOf returns the reviewed licence of a module, or "unreviewed".
func LicenseOf(path string) string {
	if license, ok := licenses[path]; ok {
		return license
	}
	return "unreviewed"
}

// FreeLicenses are the licences a dependency may carry: free, and compatible
// with distributing trebaruna under AGPL-3.0-or-later.
var FreeLicenses = map[string]bool{
	"MIT": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "Apache-2.0": true,
	"ISC": true, "MPL-2.0": true, "Zlib": true, "Unlicense": true, "CC0-1.0": true,
	"LGPL-2.1": true, "LGPL-3.0": true,
}
