//go:build !cgo

package infrastructure

import (
	"context"
	"errors"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// errNoCards is what a build without cgo answers to card management.
var errNoCards = errors.New("this build cannot use a smartcard: it was compiled without cgo\n" +
	"  use the token build: trebaruna-token")

// CardPINChanger cannot reach a card in this build.
type CardPINChanger struct{}

// ChangePIN says the build cannot use a card.
func (CardPINChanger) ChangePIN(context.Context, domain.Card, string, string) error {
	return errNoCards
}

// CardUnlocker cannot reach a card in this build.
type CardUnlocker struct{}

// UnlockPIN says the build cannot use a card.
func (CardUnlocker) UnlockPIN(context.Context, domain.Card, string, string) error { return errNoCards }

// CardPUKChanger cannot reach a card in this build.
type CardPUKChanger struct{}

// ChangePUK says the build cannot use a card.
func (CardPUKChanger) ChangePUK(context.Context, domain.Card, string, string) error {
	return errNoCards
}
