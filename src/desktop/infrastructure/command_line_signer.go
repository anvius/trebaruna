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
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"

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
		"TREBARUNA_PIN="+intent.Card.PIN,
		"TREBARUNA_TSA_PASS="+intent.TimestampPassword,
	)
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if locked(stderr.String()) {
			return domain.Receipt{}, domain.Problem{Code: domain.ProblemLockedCertificate}
		}
		if problem, refused := cardRefusal(stderr.String()); refused {
			return domain.Receipt{}, problem
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
		Document   string                          `json:"document_sha256"`
		Output     string                          `json:"signed_sha256"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		return domain.Receipt{}, fmt.Errorf("the signer printed an unreadable receipt: %w", err)
	}

	return domain.Receipt{
		SignedPath:     printed.Path,
		Standard:       printed.Standard,
		Signer:         printed.Signer,
		SignedAt:       printed.SignedAt,
		SealCount:      printed.SealCount,
		SelfSigned:     printed.SelfSigned,
		Network:        printed.Network,
		DocumentDigest: printed.Document,
		SignedDigest:   printed.Output,
	}, nil
}

// signArguments translates the intent into the command's flags.
func signArguments(intent domain.SigningIntent) []string {
	format := string(intent.Format)
	switch intent.Format {
	case domain.FormatCAdESDetached, domain.FormatCosign, domain.FormatCountersign:
		format = string(domain.FormatCAdES)
	}
	arguments := []string{
		"sign", intent.DocumentPath,
		"--format", format,
		"--level", string(intent.Level),
		"--json",
	}
	switch intent.Format {
	case domain.FormatCAdESDetached:
		arguments = append(arguments, "--detached")
	case domain.FormatCosign:
		arguments = append(arguments, "--cosign")
		// A .p7s does not carry its document: the one beside it is signed.
		if document := strings.TrimSuffix(intent.DocumentPath, ".p7s"); document != intent.DocumentPath {
			arguments = append(arguments, "--content", document)
		}
	case domain.FormatCountersign:
		arguments = append(arguments, "--countersign", "leaves")
	}

	switch {
	case intent.Card.Chosen() && intent.Card.Store == domain.StoreFirefox:
		arguments = append(arguments, "--firefox", "--certificate", intent.Card.Fingerprint)
	case intent.Card.Chosen():
		// The label narrows the readers and the fingerprint names the very
		// certificate the person picked, so the command never chooses for them.
		arguments = append(arguments, "--token", intent.Card.Token, "--certificate", intent.Card.Fingerprint)
	case strings.HasSuffix(strings.ToLower(intent.Key.Path), ".pem"):
		arguments = append(arguments, "--pem", intent.Key.Path)
	default:
		arguments = append(arguments, "--p12", intent.Key.Path)
	}
	if intent.Level.NeedsRevocation() {
		// LT and LTA embed the OCSP answers, which the command only fetches
		// when told it may use the network.
		arguments = append(arguments, "--online-revocation")
	}

	switch {
	case intent.Invisible:
		arguments = append(arguments, "--invisible")
	default:
		if intent.Seal.Page > 1 {
			arguments = append(arguments, "--page", strconv.Itoa(intent.Seal.Page))
		}
		if intent.Seal.Placed() {
			arguments = append(arguments, "--box", intent.Seal.Rect.BoxString())
		}
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

// cardRefusal recognises the card's refusals in the words the signing domain
// gives them, which the command prints unchanged.
func cardRefusal(stderr string) (domain.Problem, bool) {
	switch {
	case strings.Contains(stderr, signing.ErrWrongPIN.Error()):
		problem := domain.Problem{Code: domain.ProblemWrongPIN}
		switch {
		case strings.Contains(stderr, signing.ErrLastAttempt.Error()):
			problem.Detail = string(signing.PINFinalTry)
		case strings.Contains(stderr, signing.ErrCardLocked.Error()):
			problem.Detail = string(signing.PINLocked)
		}
		return problem, true
	case strings.Contains(stderr, signing.ErrCardLocked.Error()):
		return domain.Problem{Code: domain.ProblemCardLocked}, true
	case strings.Contains(stderr, signing.ErrPINExpired.Error()):
		return domain.Problem{Code: domain.ProblemPINExpired}, true
	case strings.Contains(stderr, signing.ErrPINMissing.Error()):
		return domain.Problem{Code: domain.ProblemMissingPIN}, true
	}
	return domain.Problem{}, false
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
