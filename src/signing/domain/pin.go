package domain

import (
	"errors"
	"fmt"
)

var (
	// ErrWrongPIN means the card refused the PIN; the card counted an attempt.
	ErrWrongPIN = errors.New("the card refused the PIN")

	// ErrCardLocked means the card accepts no more PIN attempts until it is
	// unlocked with its PUK.
	ErrCardLocked = errors.New("the card is locked: unlock it with its PUK")

	// ErrPINExpired means the card wants its PIN changed before it signs.
	ErrPINExpired = errors.New("the card asks for its PIN to be changed before it signs")

	// ErrPINMissing means no PIN was given for a card that needs one. Trying
	// an empty PIN would spend an attempt for nothing.
	ErrPINMissing = errors.New("the card needs its PIN")

	// ErrLastAttempt accompanies a refused PIN when the card has one attempt
	// left: the next mistake locks it.
	ErrLastAttempt = errors.New("one more wrong PIN locks the card")
)

// StopsCard reports whether a card error forbids trying the card again in the
// same run: another attempt with the same PIN would only spend another of the
// few the card allows before it locks.
func StopsCard(err error) bool {
	return errors.Is(err, ErrWrongPIN) || errors.Is(err, ErrCardLocked) ||
		errors.Is(err, ErrPINExpired) || errors.Is(err, ErrPINMissing) || stopsWithPUK(err)
}

// PINState is what a card says about its user PIN before anyone types it.
type PINState string

const (
	// PINReady is the ordinary case: the PIN is set and no attempt failed.
	PINReady PINState = "ready"
	// PINCountLow means a wrong PIN was entered since the last right one.
	PINCountLow PINState = "count-low"
	// PINFinalTry means one more wrong PIN locks the card.
	PINFinalTry PINState = "final-try"
	// PINLocked means the card accepts no PIN until it is unlocked.
	PINLocked PINState = "locked"
	// PINToBeChanged means the card wants a new PIN before it signs.
	PINToBeChanged PINState = "to-be-changed"
	// PINNotSet means the card has no user PIN yet.
	PINNotSet PINState = "not-set"
	// PINNotRequired means the card signs without a login.
	PINNotRequired PINState = "not-required"
)

// PINFlags are the facts a PKCS#11 token reports about its user PIN
// (CKF_USER_PIN_* and CKF_LOGIN_REQUIRED).
type PINFlags struct {
	Initialized   bool
	LoginRequired bool
	CountLow      bool
	FinalTry      bool
	Locked        bool
	ToBeChanged   bool
}

// PINStateOf ranks the flags by how much they stop the person: a locked card
// cannot be worked around, a PIN to change or to set can, and a warning about
// attempts matters only on a card that can still sign.
func PINStateOf(flags PINFlags) PINState {
	switch {
	case flags.Locked:
		return PINLocked
	case !flags.LoginRequired:
		return PINNotRequired
	case !flags.Initialized:
		return PINNotSet
	case flags.ToBeChanged:
		return PINToBeChanged
	case flags.FinalTry:
		return PINFinalTry
	case flags.CountLow:
		return PINCountLow
	default:
		return PINReady
	}
}

// Refusal is why a card in this state cannot sign, or nil when it can once the
// PIN is given. It is known before any PIN is typed, so no attempt is spent.
func (s PINState) Refusal() error {
	switch s {
	case PINLocked:
		return ErrCardLocked
	case PINToBeChanged:
		return ErrPINExpired
	case PINNotSet:
		return fmt.Errorf("%w: it has no user PIN yet", ErrPINExpired)
	default:
		return nil
	}
}

// CanSign reports whether a card in this state can sign once the PIN is given.
func (s PINState) CanSign() bool { return s.Refusal() == nil }
