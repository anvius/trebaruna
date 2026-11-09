package infrastructure

import (
	"net/url"
	"strings"
)

// SBOM is a CycloneDX 1.5 software bill of materials for one build: the
// application and every module linked into it, each with its licence and a
// package URL, so supply-chain tools can read what the binary contains
// without trusting our word for it.
type SBOM struct {
	Format      string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    sbomMeta    `json:"metadata"`
	Components  []component `json:"components"`
}

type sbomMeta struct {
	Component component `json:"component"`
}

type component struct {
	Type     string        `json:"type"`
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	PURL     string        `json:"purl,omitempty"`
	Licenses []licenseItem `json:"licenses,omitempty"`
}

type licenseItem struct {
	License struct {
		ID string `json:"id"`
	} `json:"license"`
}

// BillOfMaterials turns a build description into a CycloneDX document.
func BillOfMaterials(build Build) SBOM {
	sbom := SBOM{
		Format: "CycloneDX", SpecVersion: "1.5", Version: 1,
		Metadata: sbomMeta{Component: component{
			Type: "application", Name: "trebaruna", Version: build.Version,
			PURL:     "pkg:golang/codeberg.org/simplicer/trebaruna@" + url.PathEscape(build.Version),
			Licenses: []licenseItem{spdx(build.License)},
		}},
	}
	for _, dependency := range build.Dependencies {
		sbom.Components = append(sbom.Components, component{
			Type: "library", Name: dependency.Path, Version: dependency.Version,
			PURL:     "pkg:golang/" + strings.ToLower(dependency.Path) + "@" + url.PathEscape(dependency.Version),
			Licenses: []licenseItem{spdx(dependency.License)},
		})
	}
	return sbom
}

func spdx(identifier string) licenseItem {
	var item licenseItem
	item.License.ID = identifier
	return item
}
