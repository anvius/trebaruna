package infrastructure

import (
	"os"
	"path/filepath"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/browserstores/domain"
)

// desktopStores finds the profiles that launchers start a browser with, as
// "--profile <folder>" or "-profile <folder>" on an Exec line: how LibreWolf is
// configured on the computer this was written for. Only folders that hold a
// store are listed, named by the launcher's Name.
func desktopStores(env Environment, skip skipFunc) []domain.Store {
	if env.System != "linux" {
		return nil
	}
	var stores []domain.Store
	for _, folder := range launcherFolders(env) {
		entries, err := os.ReadDir(folder)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".desktop") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(folder, entry.Name()))
			if err != nil {
				continue
			}
			name, execs := parseDesktopEntry(string(data))
			if name == "" {
				name = strings.TrimSuffix(entry.Name(), ".desktop")
			}
			for _, exec := range execs {
				for _, argument := range profileArguments(exec) {
					directory := expandHome(argument, env.Home)
					if filepath.IsAbs(directory) && holdsStore(directory, skip) {
						stores = append(stores, domain.Store{Browser: name, Profile: filepath.Base(directory), Directory: directory})
					}
				}
			}
		}
	}
	return stores
}

// launcherFolders are the folders of .desktop launchers: the user's own, the
// user's Flatpak exports, then the system's.
func launcherFolders(env Environment) []string {
	return append([]string{
		filepath.Join(env.DataHome, "applications"),
		filepath.Join(env.Home, ".local", "share", "flatpak", "exports", "share", "applications"),
	}, env.SystemApplications...)
}

// parseDesktopEntry returns the Name of the [Desktop Entry] group and the Exec
// values of every group, the actions' included.
func parseDesktopEntry(text string) (string, []string) {
	var name string
	var execs []string
	group := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "["):
			group = strings.Trim(line, "[]")
		case strings.HasPrefix(line, "Name=") && group == "Desktop Entry" && name == "":
			name = strings.TrimPrefix(line, "Name=")
		case strings.HasPrefix(line, "Exec="):
			execs = append(execs, strings.TrimPrefix(line, "Exec="))
		}
	}
	return name, execs
}

// profileArguments returns the folders an Exec value names with --profile or
// -profile, in either form: "--profile <folder>" or "--profile=<folder>".
func profileArguments(exec string) []string {
	words := splitExec(exec)
	var folders []string
	for i, word := range words {
		switch {
		case (word == "--profile" || word == "-profile") && i+1 < len(words):
			folders = append(folders, words[i+1])
		case strings.HasPrefix(word, "--profile="):
			folders = append(folders, strings.TrimPrefix(word, "--profile="))
		}
	}
	return folders
}

// splitExec splits an Exec value into its words. Spaces separate them; double
// quotes keep a space inside a word, and inside quotes \" \\ \$ and \` stand
// for themselves.
func splitExec(exec string) []string {
	var words []string
	var word strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(exec); i++ {
		c := exec[i]
		switch {
		case quoted && c == '\\' && i+1 < len(exec):
			i++
			word.WriteByte(exec[i])
			inWord = true
		case c == '"':
			quoted = !quoted
			inWord = true
		case (c == ' ' || c == '\t') && !quoted:
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	return words
}

// expandHome replaces a leading ~/ with the home folder.
func expandHome(path, home string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}
