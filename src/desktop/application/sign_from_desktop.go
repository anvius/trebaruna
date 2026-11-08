// Package application runs a signing intent without knowing about windows.
package application

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"codeberg.org/anvius/pignus/src/desktop/domain"
)

// Signer runs the signature command.
type Signer interface {
	Run(ctx context.Context, arguments []string) (output string, err error)
}

// SignFromDesktop is the use case behind the Sign button.
//
// It validates, delegates to the command runner, and reports an outcome the
// window can render. It never touches Fyne.
type SignFromDesktop struct {
	signer Signer
	exists func(path string) bool
}

// NewSignFromDesktop wires the use case.
func NewSignFromDesktop(signer Signer, exists func(string) bool) *SignFromDesktop {
	return &SignFromDesktop{signer: signer, exists: exists}
}

// Execute validates and signs.
func (u *SignFromDesktop) Execute(ctx context.Context, intent domain.SigningIntent) (domain.Outcome, error) {
	if err := intent.Validate(); err != nil {
		return domain.Outcome{}, err
	}

	output, err := u.signer.Run(ctx, intent.Arguments())
	if err != nil {
		return domain.Outcome{RawJSON: output, Failed: true}, fmt.Errorf("%s", firstMeaningfulLine(output, err))
	}

	signedPath := intent.OutputName()
	if u.exists != nil && !u.exists(signedPath) {
		return domain.Outcome{RawJSON: output, Failed: true}, fmt.Errorf(
			"la firma no produjo %s;\n%s", signedPath, output,
		)
	}

	return domain.Outcome{SignedPath: signedPath, RawJSON: output}, nil
}

// firstMeaningfulLine extracts the most useful error line from the CLI output.
func firstMeaningfulLine(output string, fallback error) string {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Contains(strings.ToLower(trimmed), "error") ||
			strings.Contains(strings.ToLower(trimmed), "failed") {
			return trimmed
		}
	}
	if trimmed := strings.TrimSpace(output); trimmed != "" {
		return trimmed
	}
	return fallback.Error()
}

// CommandRunner executes the pignus binary.
type CommandRunner struct {
	BinaryPath string
}

// Run executes the command and returns its combined output.
func (c CommandRunner) Run(ctx context.Context, arguments []string) (string, error) {
	command := exec.CommandContext(ctx, c.BinaryPath, arguments...)
	output, err := command.CombinedOutput()
	return string(output), err
}

// compile-time checks.
var _ Signer = CommandRunner{}
