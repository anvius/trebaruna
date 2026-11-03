//go:build gui

package infrastructure

import (
	"context"
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

// runCommand executes a command and returns its combined output.
//
// Only stdout is kept for parsing; stderr is appended so a failure still shows
// something actionable in the window.
func runCommand(ctx context.Context, binary string, arguments []string) (string, error) {
	command := exec.CommandContext(ctx, binary, arguments...)
	output, err := command.CombinedOutput()
	return string(output), err
}
