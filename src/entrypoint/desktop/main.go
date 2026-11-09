//go:build gui

// Command trebaruna-desktop is the native desktop application.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	"codeberg.org/simplicer/trebaruna/src/entrypoint/serve"
)

func main() {
	language := messaging.Spanish
	if fromEnvironment, ok := os.LookupEnv("TREBARUNA_LANG"); ok {
		language = messaging.ParseLanguage(fromEnvironment)
	} else if fromLocale, ok := os.LookupEnv("LANG"); ok {
		language = messaging.ParseLanguage(fromLocale)
	}

	// Translations are installed before any widget is created: Fyne logs a
	// "Translation failure" for every key it cannot resolve at construction time
	// and then prints the raw key to the user.
	infrastructure.InstallTranslations(language)

	// A file manager launches the app with the chosen document as the first
	// argument (the desktop entry uses %U). Dropping it would mean "Open with
	// trebaruna" appears to do nothing, so the path travels into the window.
	//
	// The same slot receives fire-it:// URIs from web pages, which are not paths:
	// they carry a document plus parameters, and treating one as a filename would
	// put a URL in the file field. The URI is parsed here and only its document
	// reaches the window; approval of what follows is a separate, deliberate step.
	// An afirma:// URI is a Spanish administration page asking AutoFirma's
	// protocol: it opens the approval window, which shows the request and
	// answers the page only once the person decides.
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "afirma://") {
		infrastructure.RunPageRequest(infrastructure.Options{BinaryPath: resolveBinary(), Language: language}, os.Args[1])
		return
	}

	documentPath := ""
	if len(os.Args) > 1 {
		documentPath = serve.DocumentFromArgument(os.Args[1])
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
// trebaruna binary, so both surfaces cannot drift apart.
func resolveBinary() string {
	if explicit := os.Getenv("TREBARUNA_BIN"); explicit != "" {
		return explicit
	}
	if found, err := exec.LookPath("trebaruna"); err == nil {
		return found
	}
	for _, candidate := range []string{"/usr/local/bin/trebaruna", "/usr/bin/trebaruna"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if executable, err := os.Executable(); err == nil {
		directory := filepath.Dir(executable)
		// Inside a macOS bundle the layout is
		//   trebaruna.app/Contents/MacOS/trebaruna-desktop
		//   trebaruna.app/Contents/MacOS/trebaruna
		// so the sibling lookup is right, but Contents/Resources is also checked
		// because that is where a packager may put the CLI.
		candidates := []string{
			filepath.Join(directory, "trebaruna"),
			filepath.Join(directory, "..", "Resources", "trebaruna"),
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
	return "trebaruna"
}
