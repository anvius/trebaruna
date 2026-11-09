package infrastructure

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// openInBrowser shows an address to the person: in the program $BROWSER
// names, or the system's opener; and always on standard error, for a
// terminal with no browser at hand. The program is not waited for.
func openInBrowser(address string) error {
	fmt.Fprintf(os.Stderr, "trebaruna: authorise in your browser: %s\n", address)
	command := browserCommand(address)
	if command == nil || command.Start() != nil {
		return nil
	}
	go func() { _ = command.Wait() }()
	return nil
}

func browserCommand(address string) *exec.Cmd {
	if browser := os.Getenv("BROWSER"); browser != "" {
		return exec.Command(browser, address)
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", address)
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", address)
	}
	if path, err := exec.LookPath("xdg-open"); err == nil {
		return exec.Command(path, address)
	}
	return nil
}
