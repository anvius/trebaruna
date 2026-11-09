package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// PINUnlocker unlocks a card with its PUK and sets a new user PIN. It checks
// the PUK's state first: a locked PUK is refused without an attempt.
type PINUnlocker interface {
	UnlockPIN(ctx context.Context, card domain.Card, puk, replacement string) error
}

// UnlockCard is the use case behind `trebaruna pin unlock` and the window's
// Card → Unlock with PUK.
type UnlockCard struct {
	unlocker PINUnlocker
}

// NewUnlockCard wires the use case.
func NewUnlockCard(unlocker PINUnlocker) *UnlockCard {
	return &UnlockCard{unlocker: unlocker}
}

// Execute refuses an empty PUK or new PIN before the card is reached, then
// unlocks it.
func (u *UnlockCard) Execute(ctx context.Context, card domain.Card, puk, replacement string) error {
	if puk == "" {
		return domain.ErrPUKMissing
	}
	if err := (domain.PINLimits{}).Accept(replacement); err != nil {
		return err
	}
	return u.unlocker.UnlockPIN(ctx, card, puk, replacement)
}
