package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// PINChanger applies a PIN change or a PUK unlock to a card.
type PINChanger interface {
	Apply(ctx context.Context, change domain.PINChange) error
}

// ChangeCardPIN is the use case behind the window's Card menu: it refuses an
// incomplete or mistyped request before the card is reached, then applies it.
type ChangeCardPIN struct {
	changer PINChanger
}

// NewChangeCardPIN wires the use case.
func NewChangeCardPIN(changer PINChanger) *ChangeCardPIN {
	return &ChangeCardPIN{changer: changer}
}

// Execute validates and applies the change.
func (u *ChangeCardPIN) Execute(ctx context.Context, change domain.PINChange) error {
	if err := change.Validate(); err != nil {
		return err
	}
	return u.changer.Apply(ctx, change)
}
