package infrastructure

// No build tag: plain os/exec, tested by `make test` with a stand-in command.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// CommandLinePINChanger changes or unlocks a card's PIN, or changes its
// PUK, by running `trebaruna pin change|unlock|change-puk`, which reads the
// card before any attempt.
type CommandLinePINChanger struct {
	BinaryPath string
}

// Apply runs the command with the secrets in its environment.
func (c CommandLinePINChanger) Apply(ctx context.Context, change domain.PINChange) error {
	arguments := []string{"pin", string(change.Action), "--json"}
	if change.Token != "" {
		arguments = append(arguments, "--token", change.Token)
	}
	secret, replacement := "TREBARUNA_PIN=", "TREBARUNA_NEW_PIN="
	switch change.Action {
	case domain.UnlockPIN:
		secret = "TREBARUNA_PUK="
	case domain.ChangePUK:
		secret, replacement = "TREBARUNA_PUK=", "TREBARUNA_NEW_PUK="
	}

	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, c.BinaryPath, arguments...)
	command.Env = append(os.Environ(), secret+change.Secret, replacement+change.NewPIN)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if problem, refused := pinChangeRefusal(stderr.String()); refused {
			return problem
		}
		return errors.New(meaningfulLine(stderr.String(), "", err))
	}
	return nil
}

// pinChangeRefusal recognises the card's answers in the words the signing
// domain gives them: the PUK's, the new PIN's limits, then the PIN's.
func pinChangeRefusal(stderr string) (domain.Problem, bool) {
	switch {
	case strings.Contains(stderr, signing.ErrWrongPUK.Error()):
		problem := domain.Problem{Code: domain.ProblemWrongPUK}
		switch {
		case strings.Contains(stderr, signing.ErrLastAttempt.Error()):
			problem.Detail = string(signing.PINFinalTry)
		case strings.Contains(stderr, signing.ErrPUKLocked.Error()):
			problem.Detail = string(signing.PINLocked)
		}
		return problem, true
	case strings.Contains(stderr, signing.ErrPUKLocked.Error()):
		return domain.Problem{Code: domain.ProblemPUKLocked}, true
	case strings.Contains(stderr, signing.ErrPUKMissing.Error()):
		return domain.Problem{Code: domain.ProblemMissingPUK}, true
	case strings.Contains(stderr, signing.ErrNewPINRejected.Error()):
		return domain.Problem{Code: domain.ProblemNewPINRejected, Detail: limitsIn(stderr)}, true
	}
	return cardRefusal(stderr)
}

// limitsIn reads which limit the new PIN broke, as "min:N" or "max:N", so
// the window can say it in the person's language.
func limitsIn(stderr string) string {
	for _, limit := range []struct{ pattern, kind string }{
		{`at least (\d+)`, "min"},
		{`at most (\d+)`, "max"},
	} {
		if found := regexp.MustCompile(limit.pattern).FindStringSubmatch(stderr); found != nil {
			return limit.kind + ":" + found[1]
		}
	}
	return ""
}

// compile-time check.
var _ application.PINChanger = CommandLinePINChanger{}
