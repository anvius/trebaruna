package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// PUKChanger replaces a card's PUK, given the current one. It checks the
// PUK's state first: a locked PUK is refused without an attempt.
type PUKChanger interface {
	ChangePUK(ctx context.Context, card domain.Card, current, replacement string) error
}

// ChangeCardPUK is the use case behind `trebaruna pin change-puk` and the
// window's Card → Change the PUK.
type ChangeCardPUK struct {
	changer PUKChanger
}

// NewChangeCardPUK wires the use case.
func NewChangeCardPUK(changer PUKChanger) *ChangeCardPUK {
	return &ChangeCardPUK{changer: changer}
}

// Execute refuses an empty current or new PUK before the card is reached,
// then changes it.
func (u *ChangeCardPUK) Execute(ctx context.Context, card domain.Card, current, replacement string) error {
	if current == "" {
		return domain.ErrPUKMissing
	}
	if err := (domain.PINLimits{}).Accept(replacement); err != nil {
		return err
	}
	return u.changer.ChangePUK(ctx, card, current, replacement)
}
