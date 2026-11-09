package application_test

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

type recordingCard struct {
	calls []string
	err   error
}

func (r *recordingCard) ChangePIN(_ context.Context, _ domain.Card, current, replacement string) error {
	r.calls = append(r.calls, "change "+current+" "+replacement)
	return r.err
}

func (r *recordingCard) UnlockPIN(_ context.Context, _ domain.Card, puk, replacement string) error {
	r.calls = append(r.calls, "unlock "+puk+" "+replacement)
	return r.err
}

func someCard(t *testing.T) domain.Card {
	t.Helper()
	card, err := domain.NewCard("/usr/lib/opensc-pkcs11.so", "Carta Nazionale")
	if err != nil {
		t.Fatal(err)
	}
	return card
}

// TestAnEmptySecretNeverReachesTheCard: the card would count it.
func TestAnEmptySecretNeverReachesTheCard(t *testing.T) {
	card := &recordingCard{}
	change, unlock := application.NewChangeCardPIN(card), application.NewUnlockCard(card)

	if err := change.Execute(context.Background(), someCard(t), "", "5678"); !errors.Is(err, domain.ErrPINMissing) {
		t.Errorf("empty PIN: %v", err)
	}
	if err := change.Execute(context.Background(), someCard(t), "1234", ""); !errors.Is(err, domain.ErrNewPINRejected) {
		t.Errorf("empty new PIN: %v", err)
	}
	if err := unlock.Execute(context.Background(), someCard(t), "", "5678"); !errors.Is(err, domain.ErrPUKMissing) {
		t.Errorf("empty PUK: %v", err)
	}
	if len(card.calls) != 0 {
		t.Errorf("the card was reached: %v", card.calls)
	}
}

// TestTheCardIsAskedOnceWithWhatWasTyped.
func TestTheCardIsAskedOnceWithWhatWasTyped(t *testing.T) {
	card := &recordingCard{}
	if err := application.NewChangeCardPIN(card).Execute(context.Background(), someCard(t), "1234", "5678"); err != nil {
		t.Fatal(err)
	}
	if err := application.NewUnlockCard(card).Execute(context.Background(), someCard(t), "87654321", "2468"); err != nil {
		t.Fatal(err)
	}
	if len(card.calls) != 2 || card.calls[0] != "change 1234 5678" || card.calls[1] != "unlock 87654321 2468" {
		t.Errorf("calls %v", card.calls)
	}
}

// TestTheCardsRefusalIsReturned.
func TestTheCardsRefusalIsReturned(t *testing.T) {
	card := &recordingCard{err: domain.ErrWrongPUK}
	if err := application.NewUnlockCard(card).Execute(context.Background(), someCard(t), "0000", "2468"); !errors.Is(err, domain.ErrWrongPUK) {
		t.Errorf("got %v", err)
	}
}
