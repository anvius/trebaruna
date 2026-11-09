package domain

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	// ErrWrongPUK means the card refused the PUK; the card counted an attempt.
	ErrWrongPUK = errors.New("the card refused the PUK")

	// ErrPUKLocked means the PUK is locked too: only the card's issuer can
	// help now.
	ErrPUKLocked = errors.New("the card's PUK is locked: only its issuer can unlock it")

	// ErrPUKMissing means no PUK was given; trying an empty one would spend
	// an attempt for nothing.
	ErrPUKMissing = errors.New("the card needs its PUK")

	// ErrNewPINRejected means the new PIN does not fit the card's rules, said
	// before the card sees it.
	ErrNewPINRejected = errors.New("the new PIN does not fit the card")
)

// Card is a card (or token) in a reader, as card management names it: the
// PKCS#11 module that drives it and, when there are several cards, its label.
type Card struct {
	module string
	label  string
}

// NewCard names a card; the module is required.
func NewCard(module, label string) (Card, error) {
	if strings.TrimSpace(module) == "" {
		return Card{}, ErrTokenWithoutModule
	}
	return Card{module: module, label: label}, nil
}

// Module is the PKCS#11 library that drives the card.
func (c Card) Module() string { return c.module }

// Label is the token label, empty when the only card present is meant.
func (c Card) Label() string { return c.label }

// PINLimits are the PIN lengths a card accepts, as it declares them.
type PINLimits struct {
	Minimum int
	Maximum int
}

// Accept checks a new PIN against the limits before the card sees it: a card
// that refuses a new PIN of the wrong length is not counting an attempt, but
// the person deserves to know why without a card error code.
func (l PINLimits) Accept(pin string) error {
	length := utf8.RuneCountInString(pin)
	switch {
	case length == 0:
		return fmt.Errorf("%w: it is empty", ErrNewPINRejected)
	case l.Minimum > 0 && length < l.Minimum:
		return fmt.Errorf("%w: it has %d characters, the card wants at least %d", ErrNewPINRejected, length, l.Minimum)
	case l.Maximum > 0 && length > l.Maximum:
		return fmt.Errorf("%w: it has %d characters, the card takes at most %d", ErrNewPINRejected, length, l.Maximum)
	}
	return nil
}

// PUKStateOf ranks what a card says about its PUK (the security officer PIN
// in PKCS#11) the same way PINStateOf ranks the user PIN.
func PUKStateOf(locked, finalTry, countLow bool) PINState {
	switch {
	case locked:
		return PINLocked
	case finalTry:
		return PINFinalTry
	case countLow:
		return PINCountLow
	default:
		return PINReady
	}
}

// stopsWithPUK reports the PUK refusals, which StopsCard counts too: one
// refused PUK ends the run.
func stopsWithPUK(err error) bool {
	return errors.Is(err, ErrWrongPUK) || errors.Is(err, ErrPUKLocked) || errors.Is(err, ErrPUKMissing)
}
