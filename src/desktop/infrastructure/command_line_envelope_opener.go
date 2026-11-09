package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// CommandLineEnvelopeOpener opens an envelope by running
// `trebaruna decrypt --json` with the key chosen to sign.
type CommandLineEnvelopeOpener struct {
	BinaryPath string
}

// Open runs the command; the passphrase or the PIN travel in its
// environment, as for signing.
func (o CommandLineEnvelopeOpener) Open(ctx context.Context, intent domain.OpeningIntent) (domain.OpenedEnvelope, error) {
	arguments := append([]string{"decrypt", intent.EnvelopePath, "--json"}, keyArguments(intent.Key, intent.Card)...)
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, o.BinaryPath, arguments...)
	command.Env = append(os.Environ(),
		"TREBARUNA_PASSPHRASE="+intent.Key.Passphrase,
		"TREBARUNA_PIN="+intent.Card.PIN,
	)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return domain.OpenedEnvelope{}, keyFailure(stderr.String(), stdout.String(), err)
	}

	var printed struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		return domain.OpenedEnvelope{}, fmt.Errorf("the decrypt command printed an unreadable answer: %w", err)
	}
	return domain.OpenedEnvelope{Path: printed.Path, Size: printed.Size}, nil
}

var _ application.EnvelopeOpener = CommandLineEnvelopeOpener{}
