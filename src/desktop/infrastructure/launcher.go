//go:build gui

package infrastructure

import (
	"os/exec"
)

// lookPath wraps exec.LookPath so the window file does not import os/exec for
// a single call.
func lookPath(command string) (string, error) {
	return exec.LookPath(command)
}

// startDetached launches a command without waiting for it.
func startDetached(command string, arguments []string) error {
	return exec.Command(command, arguments...).Start()
}
