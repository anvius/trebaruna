//go:build cgo

package infrastructure

import (
	"context"
	"errors"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"github.com/miekg/pkcs11"
)

// CardPINChanger changes a card's PIN with C_SetPIN.
type CardPINChanger struct{}

// ChangePIN reads the card first: a locked card needs its PUK, and a new PIN
// outside the card's limits is refused before the card sees anything.
func (CardPINChanger) ChangePIN(_ context.Context, card domain.Card, current, replacement string) error {
	slot, err := findSlot(card.Module(), "", card.Label(), domain.ChooseCertificateBy(""))
	if err != nil {
		return err
	}
	name := fmt.Sprintf("token %q", slot.TokenLabel)
	switch slot.PINState {
	case domain.PINLocked:
		return fmt.Errorf("%w (%s)", domain.ErrCardLocked, name)
	case domain.PINNotSet:
		return fmt.Errorf("%w: it has no user PIN to change (%s)", domain.ErrPINExpired, name)
	}
	if err := slot.Limits.Accept(replacement); err != nil {
		return fmt.Errorf("%w (%s)", err, name)
	}

	// C_SetPIN on a session nobody logged into changes the user PIN, given
	// the current one: the card checks it once.
	opened, err := openSession(card.Module(), "", uint(slot.Index), pkcs11.CKU_USER, "", false)
	if err != nil {
		return err
	}
	defer opened.Close()
	if err := opened.module.context.SetPIN(opened.handle, current, replacement); err != nil {
		if refused := pinRefusal(err); refused != nil {
			return withStateAfter(refused, name, stateAfterRefusal(card.Module(), "", slot.Index, userPIN))
		}
		return fmt.Errorf("the card did not change the PIN (%s): %w", name, err)
	}
	return nil
}

// CardUnlocker unlocks a card with its PUK: C_Login as the security officer,
// then C_InitPIN with the new PIN.
type CardUnlocker struct{}

// UnlockPIN reads the card first: a locked PUK is refused without an attempt.
func (CardUnlocker) UnlockPIN(_ context.Context, card domain.Card, puk, replacement string) error {
	slot, err := findSlot(card.Module(), "", card.Label(), domain.ChooseCertificateBy(""))
	if err != nil {
		return err
	}
	name := fmt.Sprintf("token %q", slot.TokenLabel)
	if slot.PUKState == domain.PINLocked {
		return fmt.Errorf("%w (%s)", domain.ErrPUKLocked, name)
	}
	if err := slot.Limits.Accept(replacement); err != nil {
		return fmt.Errorf("%w (%s)", err, name)
	}

	opened, err := openSession(card.Module(), "", uint(slot.Index), pkcs11.CKU_SO, puk, true)
	if err != nil {
		if refused := pukRefusal(err); refused != nil {
			return withStateAfter(refused, name, stateAfterRefusal(card.Module(), "", slot.Index, cardPUK))
		}
		return fmt.Errorf("cannot open %s with module %s: %w", name, card.Module(), err)
	}
	defer opened.Close()
	if err := opened.module.context.InitPIN(opened.handle, replacement); err != nil {
		return fmt.Errorf("the card did not take the new PIN (%s): %w", name, err)
	}
	return nil
}

// CardPUKChanger replaces a card's PUK: C_Login as the security officer
// with the current PUK, then C_SetPIN, which in that session changes the
// security officer's PIN.
type CardPUKChanger struct{}

// ChangePUK reads the card first: a locked PUK, or a new one outside the
// card's limits, is refused without an attempt.
func (CardPUKChanger) ChangePUK(_ context.Context, card domain.Card, current, replacement string) error {
	slot, err := findSlot(card.Module(), "", card.Label(), domain.ChooseCertificateBy(""))
	if err != nil {
		return err
	}
	name := fmt.Sprintf("token %q", slot.TokenLabel)
	if slot.PUKState == domain.PINLocked {
		return fmt.Errorf("%w (%s)", domain.ErrPUKLocked, name)
	}
	if err := slot.Limits.Accept(replacement); err != nil {
		return fmt.Errorf("the new PUK: %w (%s)", err, name)
	}

	opened, err := openSession(card.Module(), "", uint(slot.Index), pkcs11.CKU_SO, current, true)
	if err != nil {
		if refused := pukRefusal(err); refused != nil {
			return withStateAfter(refused, name, stateAfterRefusal(card.Module(), "", slot.Index, cardPUK))
		}
		return fmt.Errorf("cannot open %s with module %s: %w", name, card.Module(), err)
	}
	defer opened.Close()
	if err := opened.module.context.SetPIN(opened.handle, current, replacement); err != nil {
		return fmt.Errorf("the card did not change the PUK (%s): %w", name, err)
	}
	return nil
}

// pukRefusal translates the card's answer to a PUK login.
func pukRefusal(err error) error {
	var code pkcs11.Error
	if !errors.As(err, &code) {
		return nil
	}
	switch code {
	case pkcs11.CKR_PIN_INCORRECT, pkcs11.CKR_PIN_LEN_RANGE:
		return domain.ErrWrongPUK
	case pkcs11.CKR_PIN_LOCKED:
		return domain.ErrPUKLocked
	}
	return nil
}

// compile-time checks.
var (
	_ application.PINChanger  = CardPINChanger{}
	_ application.PINUnlocker = CardUnlocker{}
	_ application.PUKChanger  = CardPUKChanger{}
)
