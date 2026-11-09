package infrastructure

// No build tag: plain os/exec, tested by `make test` with a stand-in command.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// CommandLineRecipientBook reaches the address book through `trebaruna
// recipients list|add|remove`.
type CommandLineRecipientBook struct {
	BinaryPath string
}

// Saved lists the book.
func (b CommandLineRecipientBook) Saved(ctx context.Context) ([]domain.SavedRecipient, error) {
	output, err := b.run(ctx, "list")
	if err != nil {
		return nil, err
	}
	var listed struct {
		Recipients []struct {
			Holder      string `json:"holder"`
			Fingerprint string `json:"fingerprint"`
			NotAfter    string `json:"not_after"`
			Path        string `json:"path"`
		} `json:"recipients"`
	}
	if err := json.Unmarshal(output, &listed); err != nil {
		return nil, fmt.Errorf("the address book could not be read: %w", err)
	}
	saved := make([]domain.SavedRecipient, 0, len(listed.Recipients))
	for _, recipient := range listed.Recipients {
		notAfter, _ := time.Parse(time.RFC3339, recipient.NotAfter)
		saved = append(saved, domain.SavedRecipient{Holder: recipient.Holder, Fingerprint: recipient.Fingerprint,
			NotAfter: notAfter, Path: recipient.Path})
	}
	return saved, nil
}

// Keep saves the certificate of a file.
func (b CommandLineRecipientBook) Keep(ctx context.Context, path string) error {
	_, err := b.run(ctx, "add", path)
	return err
}

// Forget removes a certificate by fingerprint.
func (b CommandLineRecipientBook) Forget(ctx context.Context, fingerprint string) error {
	_, err := b.run(ctx, "remove", fingerprint)
	return err
}

func (b CommandLineRecipientBook) run(ctx context.Context, arguments ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, b.BinaryPath, append(append([]string{"recipients"}, arguments...), "--json")...)
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return nil, errors.New(meaningfulLine(stderr.String(), "", err))
	}
	return stdout.Bytes(), nil
}

// compile-time check.
var _ application.RecipientBook = CommandLineRecipientBook{}
