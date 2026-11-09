package infrastructure

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
)

// CommandLineLocalChannel runs `trebaruna afirma local-tls <action>`.
type CommandLineLocalChannel struct {
	BinaryPath string
}

// Run returns what the command printed.
func (c CommandLineLocalChannel) Run(ctx context.Context, action string) (string, error) {
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, c.BinaryPath, "afirma", "local-tls", action)
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return "", errors.New(meaningfulLine(stderr.String(), stdout.String(), err))
	}
	return strings.TrimSpace(stdout.String()), nil
}

var _ application.LocalChannelCertificate = CommandLineLocalChannel{}
