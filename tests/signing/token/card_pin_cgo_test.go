//go:build cgo

package infrastructure_test

// Changing and unlocking the PIN, checked against SoftHSM, whose security
// officer PIN plays the PUK.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

func cardOf(t *testing.T, token softHSM) domain.Card {
	t.Helper()
	card, err := domain.NewCard(token.module, token.label)
	if err != nil {
		t.Fatal(err)
	}
	return card
}

// signsWith reports whether the card signs with this PIN.
func signsWith(t *testing.T, token softHSM, pin string) error {
	t.Helper()
	_, err := loadFromCard(t, token.module, token.label, pin, domain.ChooseCertificateBy(""))
	return err
}

// TestThePINIsChangedWithTheCurrentOne: afterwards the card takes the new PIN
// and refuses the old.
func TestThePINIsChangedWithTheCurrentOne(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	if err := (infrastructure.CardPINChanger{}).ChangePIN(context.Background(), cardOf(t, token), token.pin, "5678"); err != nil {
		t.Fatalf("change: %v", err)
	}
	if err := signsWith(t, token, "5678"); err != nil {
		t.Errorf("the new PIN must sign: %v", err)
	}
	if err := signsWith(t, token, token.pin); !errors.Is(err, domain.ErrWrongPIN) {
		t.Errorf("the old PIN must be refused, got %v", err)
	}
}

// TestAWrongCurrentPINChangesNothing.
func TestAWrongCurrentPINChangesNothing(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	err := (infrastructure.CardPINChanger{}).ChangePIN(context.Background(), cardOf(t, token), "0000", "5678")
	if !errors.Is(err, domain.ErrWrongPIN) {
		t.Fatalf("a wrong current PIN must be named, got %v", err)
	}
	if err := signsWith(t, token, token.pin); err != nil {
		t.Errorf("the PIN must be unchanged: %v", err)
	}
}

// TestANewPINTheCardCannotTakeIsRefusedFirst: SoftHSM wants at least four
// characters; the card is not asked.
func TestANewPINTheCardCannotTakeIsRefusedFirst(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	err := (infrastructure.CardPINChanger{}).ChangePIN(context.Background(), cardOf(t, token), token.pin, "12")
	if !errors.Is(err, domain.ErrNewPINRejected) || !strings.Contains(err.Error(), "at least 4") {
		t.Fatalf("a short PIN must be refused with the card's limit, got %v", err)
	}
}

// TestThePUKSetsANewPIN: the PUK opens the card and the new PIN signs.
func TestThePUKSetsANewPIN(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	if err := (infrastructure.CardUnlocker{}).UnlockPIN(context.Background(), cardOf(t, token), environment.soPin, "2468"); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := signsWith(t, token, "2468"); err != nil {
		t.Errorf("the new PIN must sign: %v", err)
	}
}

// TestAWrongPUKIsNamedAsSuch.
func TestAWrongPUKIsNamedAsSuch(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	err := (infrastructure.CardUnlocker{}).UnlockPIN(context.Background(), cardOf(t, token), "000000", "2468")
	if !errors.Is(err, domain.ErrWrongPUK) {
		t.Fatalf("a wrong PUK must be named, got %v", err)
	}
	if err := signsWith(t, token, token.pin); err != nil {
		t.Errorf("the PIN must be unchanged: %v", err)
	}
}

// TestTheCommandLineChangesThePINFromTheEnvironment: no secret on the
// command line.
func TestTheCommandLineChangesThePINFromTheEnvironment(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")
	t.Setenv("TREBARUNA_PIN", token.pin)
	t.Setenv("TREBARUNA_NEW_PIN", "97531")

	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"pin", "change", "--module", token.module, "--token", token.label}, &stdout, &stderr); code != 0 {
		t.Fatalf("pin change exited %d: %s", code, stderr.String())
	}
	if err := signsWith(t, token, "97531"); err != nil {
		t.Errorf("the new PIN must sign: %v", err)
	}

	t.Setenv("TREBARUNA_PUK", "")
	stdout.Reset()
	stderr.Reset()
	if code := cli.Run([]string{"pin", "unlock", "--module", token.module, "--token", token.label}, &stdout, &stderr); code == 0 ||
		!strings.Contains(stderr.String(), domain.ErrPUKMissing.Error()) {
		t.Errorf("an empty PUK must be refused before the card: %d %s", code, stderr.String())
	}
}
