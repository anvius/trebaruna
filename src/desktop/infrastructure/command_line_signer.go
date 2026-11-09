package infrastructure

// This file carries no build tag on purpose: the adapter is plain os/exec, and
// keeping it outside the gui tag lets `make test` exercise it on every machine.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"

	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
)

// CommandLineSigner signs by running `trebaruna sign --json`.
//
// The desktop is a frontend of the command, not a second implementation: one
// list of flags, one validation path, and nothing to keep in sync.
type CommandLineSigner struct {
	BinaryPath string
}

// Sign runs the command and reads the receipt it prints.
func (s CommandLineSigner) Sign(ctx context.Context, intent domain.SigningIntent) (domain.Receipt, error) {
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, s.BinaryPath, signArguments(intent)...)
	// Secrets travel in the environment, never as --pass or --tsa-pass: any
	// local user can list command lines, only the owner can read the environment.
	command.Env = append(os.Environ(),
		"TREBARUNA_PASSPHRASE="+intent.Key.Passphrase,
		"TREBARUNA_TSA_PASS="+intent.TimestampPassword,
	)
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if locked(stderr.String()) {
			return domain.Receipt{}, domain.Problem{Code: domain.ProblemLockedCertificate}
		}
		return domain.Receipt{}, errors.New(meaningfulLine(stderr.String(), stdout.String(), err))
	}

	var printed struct {
		Path       string                          `json:"path"`
		Standard   string                          `json:"standard"`
		Signer     string                          `json:"signer"`
		SignedAt   string                          `json:"signed_at"`
		SealCount  int                             `json:"seal_count"`
		SelfSigned bool                            `json:"self_signed"`
		Network    []transparencydomain.Connection `json:"network"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		return domain.Receipt{}, fmt.Errorf("the signer printed an unreadable receipt: %w", err)
	}

	return domain.Receipt{
		SignedPath: printed.Path,
		Standard:   printed.Standard,
		Signer:     printed.Signer,
		SignedAt:   printed.SignedAt,
		SealCount:  printed.SealCount,
		SelfSigned: printed.SelfSigned,
		Network:    printed.Network,
	}, nil
}

// signArguments translates the intent into the command's flags.
func signArguments(intent domain.SigningIntent) []string {
	arguments := []string{
		"sign", intent.DocumentPath,
		"--format", string(intent.Format),
		"--level", string(intent.Level),
		"--json",
	}

	if strings.HasSuffix(strings.ToLower(intent.Key.Path), ".pem") {
		arguments = append(arguments, "--pem", intent.Key.Path)
	} else {
		arguments = append(arguments, "--p12", intent.Key.Path)
	}
	if intent.Level.NeedsRevocation() {
		// LT and LTA embed the OCSP answers, which the command only fetches
		// when told it may use the network.
		arguments = append(arguments, "--online-revocation")
	}

	if intent.Seal.Page > 1 {
		arguments = append(arguments, "--page", strconv.Itoa(intent.Seal.Page))
	}
	if intent.Seal.Placed() {
		arguments = append(arguments, "--box", intent.Seal.Rect.BoxString())
	}
	if intent.TimestampURL != "" {
		arguments = append(arguments, "--tsa", intent.TimestampURL)
	}
	if intent.TimestampUser != "" {
		arguments = append(arguments, "--tsa-user", intent.TimestampUser)
	}
	if intent.Reason != "" {
		arguments = append(arguments, "--reason", intent.Reason)
	}
	if intent.Location != "" {
		arguments = append(arguments, "--location", intent.Location)
	}
	return arguments
}

// locked recognises a passphrase that does not open the certificate, in the
// words both the certificate and the sign commands use for it.
func locked(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "passphrase does not open") ||
		strings.Contains(lower, "decryption password incorrect")
}

// meaningfulLine picks the line a user can act on: the command explains its
// failures on stderr, so that is read first, and the exit status is the last
// resort because "exit status 4" tells nobody what to fix.
func meaningfulLine(stderr, stdout string, fallback error) string {
	for _, output := range []string{stderr, stdout} {
		for _, line := range strings.Split(output, "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				return trimmed
			}
		}
	}
	return fallback.Error()
}

// compile-time check.
var _ application.Signer = CommandLineSigner{}
