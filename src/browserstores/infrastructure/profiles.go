package infrastructure

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// profileEntry is a profile folder an installation names, and whether the
// installation opens it first.
type profileEntry struct {
	directory string
	isDefault bool
}

// iniSection is one [section] of an .ini file and its key=value pairs.
type iniSection struct {
	name   string
	values map[string]string
}

// readProfiles lists the profile folders of a Firefox-style installation in
// the order it opens them: the profile its installs.ini (or an [Install…]
// section of profiles.ini) names first, then the one marked Default=1, then
// the rest. Folders that do not exist are listed too; holdsStore drops them.
func readProfiles(folder string, skip skipFunc) []profileEntry {
	var installs, marked, others []profileEntry
	for _, name := range []string{"profiles.ini", "installs.ini"} {
		path := filepath.Join(folder, name)
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				skip(path, err.Error())
			}
			continue
		}
		for _, section := range parseINI(string(data)) {
			switch {
			case name == "installs.ini" || strings.HasPrefix(section.name, "Install"):
				if path := section.values["Default"]; path != "" {
					installs = append(installs, profileEntry{directory: profilePath(folder, path), isDefault: true})
				}
			case strings.HasPrefix(section.name, "Profile") && section.values["Path"] != "":
				entry := profileEntry{directory: profilePath(folder, section.values["Path"]), isDefault: section.values["Default"] == "1"}
				if entry.isDefault {
					marked = append(marked, entry)
				} else {
					others = append(others, entry)
				}
			}
		}
	}
	return append(append(installs, marked...), others...)
}

// profilePath is the folder a profile path names. A relative path (IsRelative=1,
// the default) is inside the folder that holds profiles.ini; an absolute one
// (IsRelative=0) is used as it is.
func profilePath(folder, path string) string {
	path = filepath.FromSlash(path)
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(folder, path)
}

// parseINI reads .ini text: sections in order, keys case-sensitive, comments
// and blank lines skipped, keys before any section ignored.
func parseINI(text string) []iniSection {
	var sections []iniSection
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			sections = append(sections, iniSection{name: strings.Trim(line, "[]"), values: map[string]string{}})
		case len(sections) > 0:
			if key, value, ok := strings.Cut(line, "="); ok {
				sections[len(sections)-1].values[strings.TrimSpace(key)] = strings.TrimSpace(value)
			}
		}
	}
	return sections
}
