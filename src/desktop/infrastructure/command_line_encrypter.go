package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// CommandLineEncrypter encrypts by running `trebaruna encrypt --json`.
type CommandLineEncrypter struct {
	BinaryPath string
}

// Encrypt runs the command with a --to for each recipient.
func (e CommandLineEncrypter) Encrypt(ctx context.Context, intent domain.EncryptionIntent) (domain.SealedEnvelope, error) {
	arguments := []string{"encrypt", intent.DocumentPath, "--json"}
	for _, recipient := range intent.Recipients {
		arguments = append(arguments, "--to", recipient)
	}
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, e.BinaryPath, arguments...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return domain.SealedEnvelope{}, errors.New(meaningfulLine(stderr.String(), stdout.String(), err))
	}

	var printed struct {
		Path       string   `json:"path"`
		Recipients []string `json:"recipients"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		return domain.SealedEnvelope{}, fmt.Errorf("the encrypt command printed an unreadable answer: %w", err)
	}
	return domain.SealedEnvelope{Path: printed.Path, Recipients: printed.Recipients}, nil
}

var _ application.Encrypter = CommandLineEncrypter{}
