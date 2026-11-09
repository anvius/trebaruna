package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// PINChanger changes the user PIN of a card, given the current one. It checks
// what the card says before any attempt: a locked card, or a new PIN outside
// the card's limits, is refused without the card counting a try.
type PINChanger interface {
	ChangePIN(ctx context.Context, card domain.Card, current, replacement string) error
}

// ChangeCardPIN is the use case behind `trebaruna pin change` and the
// window's Card → Change PIN.
type ChangeCardPIN struct {
	changer PINChanger
}

// NewChangeCardPIN wires the use case.
func NewChangeCardPIN(changer PINChanger) *ChangeCardPIN {
	return &ChangeCardPIN{changer: changer}
}

// Execute refuses an empty PIN or new PIN before the card is reached, then
// changes it.
func (u *ChangeCardPIN) Execute(ctx context.Context, card domain.Card, current, replacement string) error {
	if current == "" {
		return domain.ErrPINMissing
	}
	if err := (domain.PINLimits{}).Accept(replacement); err != nil {
		return err
	}
	return u.changer.ChangePIN(ctx, card, current, replacement)
}
