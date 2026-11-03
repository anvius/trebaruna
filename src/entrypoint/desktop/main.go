//go:build gui

// Command firma-it-desktop is the native desktop application.
package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"codeberg.org/simplicer/firma-it/src/desktop/infrastructure"
	"codeberg.org/simplicer/firma-it/src/desktop/messaging"
)

func main() {
	language := messaging.Spanish
	if fromEnvironment, ok := os.LookupEnv("FIRMA_IT_LANG"); ok {
		language = messaging.ParseLanguage(fromEnvironment)
	} else if fromLocale, ok := os.LookupEnv("LANG"); ok {
		language = messaging.ParseLanguage(fromLocale)
	}

	// Translations are installed before any widget is created: Fyne logs a
	// "Translation failure" for every key it cannot resolve at construction time
	// and then prints the raw key to the user.
	infrastructure.InstallTranslations(language)

	// A file manager launches the app with the chosen document as the first
	// argument (the desktop entry uses %f). Dropping it would mean "Open with
	// firma-it" appears to do nothing, so the path travels into the window.
	documentPath := ""
	if len(os.Args) > 1 {
		documentPath = os.Args[1]
	}

	infrastructure.NewWindow(infrastructure.Options{
		BinaryPath:   resolveBinary(),
		Language:     language,
		DocumentPath: documentPath,
	}).Run()
}

// resolveBinary finds the CLI the window will drive.
//
// The GUI is a frontend, not a second implementation: it shells out to the same
// firma-it binary, so both surfaces cannot drift apart.
func resolveBinary() string {
	if explicit := os.Getenv("FIRMA_IT_BIN"); explicit != "" {
		return explicit
	}
	if found, err := exec.LookPath("firma-it"); err == nil {
		return found
	}
	for _, candidate := range []string{"/usr/local/bin/firma-it", "/usr/bin/firma-it"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if executable, err := os.Executable(); err == nil {
		directory := filepath.Dir(executable)
		// Inside a macOS bundle the layout is
		//   Firma-it.app/Contents/MacOS/firma-it-desktop
		//   Firma-it.app/Contents/MacOS/firma-it
		// so the sibling lookup is right, but Contents/Resources is also checked
		// because that is where a packager may put the CLI.
		candidates := []string{
			filepath.Join(directory, "firma-it"),
			filepath.Join(directory, "..", "Resources", "firma-it"),
		}
		for _, candidate := range candidates {
			if _, statErr := os.Stat(candidate); statErr == nil {
				absolute, absErr := filepath.Abs(candidate)
				if absErr == nil {
					return absolute
				}
				return candidate
			}
		}
	}
	return "firma-it"
}
