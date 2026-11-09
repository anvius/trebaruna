package packaging_test

// The packages agree with each other and with the source: one application id,
// the release in VERSION, the Go the project needs, AutoFirma's links left
// to AutoFirma unless the person chooses, and an AppImage that is the window
// or the command line depending on its name. The .deb itself is built and
// checked with dpkg-deb, apt and the extracted binaries (packaging/build-deb.sh).

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const applicationID = "org.codeberg.simplicer.trebaruna"

func readPackaging(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

// TestTheAppStreamDescriptionMatchesTheSource: its id is the window's, its
// newest release the version in VERSION, its launcher the one installed.
func TestTheAppStreamDescriptionMatchesTheSource(t *testing.T) {
	var component struct {
		ID         string `xml:"id"`
		License    string `xml:"project_license"`
		Launchable string `xml:"launchable"`
		Releases   []struct {
			Version string `xml:"version,attr"`
		} `xml:"releases>release"`
	}
	if err := xml.Unmarshal([]byte(readPackaging(t, "packaging/"+applicationID+".metainfo.xml")), &component); err != nil {
		t.Fatal(err)
	}
	version := strings.TrimSpace(readPackaging(t, "VERSION"))
	if component.ID != applicationID || component.License != "AGPL-3.0-or-later" || len(component.Releases) == 0 ||
		component.Releases[0].Version != version {
		t.Errorf("metainfo %+v, VERSION %s", component, version)
	}
	if _, err := os.Stat(filepath.Join("..", "..", "packaging", component.Launchable)); err != nil {
		t.Errorf("launchable %q: %v", component.Launchable, err)
	}
	if !strings.Contains(readPackaging(t, "src/desktop/infrastructure/window.go"), `app.NewWithID("`+applicationID+`")`) {
		t.Error("the window runs under another application id")
	}
}

// TestTheFlatpakBuildsWithTheGoTheProjectNeeds, under the same id, without
// reaching the host's files beyond the home folder.
func TestTheFlatpakBuildsWithTheGoTheProjectNeeds(t *testing.T) {
	manifest := readPackaging(t, "packaging/flatpak/"+applicationID+".yml")
	goMod := readPackaging(t, "go.mod")
	required := regexp.MustCompile(`(?m)^go (\d+\.\d+)`).FindStringSubmatch(goMod)
	if required == nil {
		t.Fatal("go.mod states no Go version")
	}
	for _, want := range []string{"id: " + applicationID, "command: trebaruna-desktop", "go" + required[1] + ".", "GOFLAGS: -mod=vendor"} {
		if !strings.Contains(manifest, want) {
			t.Errorf("the manifest lacks %q", want)
		}
	}
	if strings.Contains(manifest, "--filesystem=host") {
		t.Error("the Flatpak reaches the whole host file system")
	}
}

// TestTheWindowsInstallerLeavesAfirmaLinksToTheirOwner: trebaruna:// is
// registered with the program, afirma:// only through a feature that is off
// by default.
func TestTheWindowsInstallerLeavesAfirmaLinksToTheirOwner(t *testing.T) {
	var installer struct {
		Package struct {
			UpgradeCode string `xml:"UpgradeCode,attr"`
			Scope       string `xml:"Scope,attr"`
			Features    []struct {
				ID         string `xml:"Id,attr"`
				Level      string `xml:"Level,attr"`
				Components []struct {
					ID string `xml:"Id,attr"`
				} `xml:"ComponentRef"`
			} `xml:"Feature"`
		} `xml:"Package"`
	}
	source := readPackaging(t, "packaging/windows/trebaruna.wxs")
	if err := xml.Unmarshal([]byte(source), &installer); err != nil {
		t.Fatal(err)
	}
	if installer.Package.UpgradeCode != "77e67d8a-3761-4bc1-8466-1c3b7fc96bcd" || installer.Package.Scope != "perUser" {
		t.Errorf("package %+v", installer.Package)
	}
	where := map[string]string{}
	for _, feature := range installer.Package.Features {
		for _, component := range feature.Components {
			where[component.ID] = feature.ID + "/" + feature.Level
		}
	}
	if where["Programs"] != "Main/1" || where["TrebarunaLinks"] != "Main/1" || where["AfirmaLinks"] != "Afirma/2" {
		t.Errorf("components by feature: %v", where)
	}
	if !strings.Contains(source, `Key="Software\Classes\afirma"`) || !strings.Contains(source, `Key="Software\Classes\trebaruna"`) {
		t.Error("the URL schemes are not registered")
	}
}

// TestTheAppImageIsTheWindowOrTheCommandLineByItsName.
func TestTheAppImageIsTheWindowOrTheCommandLineByItsName(t *testing.T) {
	appdir := t.TempDir()
	for name, says := range map[string]string{"trebaruna": "command line", "trebaruna-desktop": "window"} {
		path := filepath.Join(appdir, "usr", "bin", name)
		os.MkdirAll(filepath.Dir(path), 0o755)
		os.WriteFile(path, []byte("#!/bin/sh\necho "+says+" \"$@\"\n"), 0o755)
	}
	apprun := filepath.Join(appdir, "AppRun")
	os.WriteFile(apprun, []byte(readPackaging(t, "packaging/appimage/AppRun")), 0o755)
	for argv0, want := range map[string]string{
		"/home/mario/.local/bin/trebaruna":           "command line verify a.pdf",
		"/home/mario/Apps/trebaruna-x86_64.AppImage": "window verify a.pdf",
	} {
		command := exec.Command(apprun, "verify", "a.pdf")
		command.Env = append(os.Environ(), "ARGV0="+argv0)
		output, err := command.Output()
		if err != nil || strings.TrimSpace(string(output)) != want {
			t.Errorf("run as %s: %q %v", argv0, output, err)
		}
	}
}
