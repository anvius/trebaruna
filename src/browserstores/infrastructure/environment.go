// Package infrastructure finds the NSS certificate stores of a user's browsers
// and mail clients on this computer, from the profile folders each program
// keeps and the launchers that name a profile (ADR-0020).
package infrastructure

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Environment is where discovery looks: the user's home folder and the folders
// the system keeps settings and launchers in. Tests build one inside a
// temporary folder; the program reads its own with FromSystem.
type Environment struct {
	// Home is the user's home folder.
	Home string
	// System is the operating system: "linux", "darwin" or "windows".
	System string
	// ConfigHome and DataHome are the XDG folders of the user's session.
	ConfigHome string
	DataHome   string
	// AppData is %APPDATA% on Windows.
	AppData string
	// SystemApplications are the system-wide folders of .desktop launchers.
	SystemApplications []string
}

// NewEnvironment is the environment of a user whose folders are the defaults
// under home. It reads no variable and no folder outside home.
func NewEnvironment(home, system string) Environment {
	return Environment{
		Home:       home,
		System:     system,
		ConfigHome: filepath.Join(home, ".config"),
		DataHome:   filepath.Join(home, ".local", "share"),
	}
}

// FromSystem is the environment of the running program. Inside a Flatpak
// sandbox XDG_CONFIG_HOME and XDG_DATA_HOME point into ~/.var/app, where the
// host's browsers keep nothing, so the defaults under the home folder are used.
func FromSystem() (Environment, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Environment{}, err
	}
	env := NewEnvironment(home, runtime.GOOS)
	env.AppData = os.Getenv("APPDATA")
	env.ConfigHome = xdgFolder(os.Getenv("XDG_CONFIG_HOME"), env.ConfigHome, home)
	env.DataHome = xdgFolder(os.Getenv("XDG_DATA_HOME"), env.DataHome, home)
	if env.System == "linux" {
		env.SystemApplications = []string{
			"/var/lib/flatpak/exports/share/applications",
			"/usr/local/share/applications",
			"/usr/share/applications",
		}
	}
	return env, nil
}

// xdgFolder is the folder an XDG variable names, when it is an absolute path
// outside the sandboxes under ~/.var/app; otherwise the fallback.
func xdgFolder(value, fallback, home string) string {
	sandboxes := filepath.Join(home, ".var", "app") + string(filepath.Separator)
	if !filepath.IsAbs(value) || strings.HasPrefix(value, sandboxes) {
		return fallback
	}
	return value
}
