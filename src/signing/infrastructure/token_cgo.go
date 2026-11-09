//go:build cgo

package infrastructure

import (
	"errors"
	"fmt"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"github.com/miekg/pkcs11"
)

// openToken opens a session on the card (or software store) that signs.
//
// The card is found and its PIN state read before any login, so a locked card
// or a missing PIN is reported without spending an attempt. Guarded by the cgo
// build tag: the static binary (P12/PEM only) omits it.
func openToken(signer domain.Signer) (tokenContext, error) {
	slot, err := slotFor(signer)
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("token %q", slot.TokenLabel)

	if refusal := slot.PINState.Refusal(); refusal != nil {
		return nil, fmt.Errorf("%w (%s)", refusal, name)
	}
	// A reader with a keypad takes the PIN itself; anywhere else an empty PIN
	// is a wrong PIN, and the card would count it.
	if signer.PKCS11PIN() == "" && slot.PINState != domain.PINNotRequired && !slot.PINPad {
		return nil, fmt.Errorf("%w (%s): give it in $TREBARUNA_PIN", domain.ErrPINMissing, name)
	}

	opened, err := openSession(signer.PKCS11Module(), signer.PKCS11Parameters(), uint(slot.Index),
		pkcs11.CKU_USER, signer.PKCS11PIN(), slot.PINState != domain.PINNotRequired)
	if err != nil {
		if refused := pinRefusal(err); refused != nil {
			return nil, withStateAfter(refused, name,
				stateAfterRefusal(signer.PKCS11Module(), signer.PKCS11Parameters(), slot.Index, userPIN))
		}
		return nil, fmt.Errorf(
			"cannot open %s with module %s: %w\n"+
				"  check: systemctl status pcscd ; pcsc_scan ; pkcs11-tool -L",
			name, signer.PKCS11Module(), err,
		)
	}
	return opened, nil
}

// pinRefusal translates the card's answer to a login into the business error,
// or nil when the failure is not about the PIN.
func pinRefusal(err error) error {
	var code pkcs11.Error
	if !errors.As(err, &code) {
		return nil
	}
	switch code {
	case pkcs11.CKR_PIN_INCORRECT, pkcs11.CKR_PIN_LEN_RANGE:
		return domain.ErrWrongPIN
	case pkcs11.CKR_PIN_LOCKED:
		return domain.ErrCardLocked
	case pkcs11.CKR_PIN_EXPIRED:
		return domain.ErrPINExpired
	}
	return nil
}

// secretState reads one secret's state from a slot: the user PIN's or the
// PUK's, with the error that says it is now locked.
type secretState struct {
	read   func(TokenSlot) domain.PINState
	locked error
}

var (
	userPIN = secretState{read: func(slot TokenSlot) domain.PINState { return slot.PINState }, locked: domain.ErrCardLocked}
	cardPUK = secretState{read: func(slot TokenSlot) domain.PINState { return slot.PUKState }, locked: domain.ErrPUKLocked}
)

// stateAfterRefusal reads the card again after a refused PIN or PUK, so the
// message says whether the next mistake locks it (ErrLastAttempt) or it just
// did.
func stateAfterRefusal(module, parameters string, index int, secret secretState) error {
	slots, err := inspectToken(module, parameters, "")
	if err != nil {
		return nil
	}
	for _, slot := range slots {
		if slot.Index != index {
			continue
		}
		switch secret.read(slot) {
		case domain.PINFinalTry:
			return domain.ErrLastAttempt
		case domain.PINLocked:
			return secret.locked
		}
	}
	return nil
}

// withStateAfter names a refusal, the token, and what the card said
// afterwards when it adds something.
func withStateAfter(refused error, name string, state error) error {
	if state != nil && !errors.Is(refused, state) {
		return fmt.Errorf("%w (%s): %w", refused, name, state)
	}
	return fmt.Errorf("%w (%s)", refused, name)
}

// slotFor finds the reader whose card signs.
//
// With a label, the card with that label; two cards with the same label, such
// as two identity cards, are told apart by the certificate. Without one, the
// card that holds the certificate named, or the only card present.
//
// The cards are read without a PIN: trying the PIN on every card in every
// reader would spend the attempts of cards that are not the one meant. A card
// that shows no certificate before login is still found when it is the only
// card that fits.
func slotFor(signer domain.Signer) (TokenSlot, error) {
	return findSlot(signer.PKCS11Module(), signer.PKCS11Parameters(), signer.PKCS11Token(), signer.CertificateChoice())
}

// findSlot is slotFor for any module, label and certificate choice.
func findSlot(module, parameters, label string, choice domain.CertificateChoice) (TokenSlot, error) {
	slots, err := inspectToken(module, parameters, "")
	if err != nil {
		return TokenSlot{}, err
	}

	var present []TokenSlot
	for _, slot := range slots {
		if slot.TokenLabel != "" && (label == "" || slot.TokenLabel == label) {
			present = append(present, slot)
		}
	}
	if len(present) == 0 && label != "" {
		return TokenSlot{}, fmt.Errorf("no card labelled %q in the readers of %s; list them with: trebaruna token",
			label, module)
	}
	if len(present) == 1 && label != "" {
		return present[0], nil
	}

	var holding []TokenSlot
	for _, slot := range present {
		if _, err := choice.Pick(parsedCertificates(slot.Certificates)); !errors.Is(err, domain.ErrNoCertificateMatches) {
			holding = append(holding, slot)
		}
	}
	if len(holding) == 0 && choice.Automatic() && len(present) == 1 {
		holding = present
	}

	switch len(holding) {
	case 1:
		return holding[0], nil
	case 0:
		if choice.Automatic() {
			return TokenSlot{}, fmt.Errorf("no card in the readers of %s shows a certificate.\n"+
				"  check: the card is inserted and pcscd is running; list them with: trebaruna token",
				module)
		}
		return TokenSlot{}, fmt.Errorf("%w %q in any reader of %s; list them with: trebaruna token",
			domain.ErrNoCertificateMatches, choice.String(), module)
	default:
		labels := make([]string, len(holding))
		for index, slot := range holding {
			labels[index] = fmt.Sprintf("%q in %s", slot.TokenLabel, slot.Description)
		}
		return TokenSlot{}, fmt.Errorf("several cards can sign (%s): name the certificate to use",
			strings.Join(labels, ", "))
	}
}

// PKCS11Available reports that this build can talk to smartcards and tokens.
const PKCS11Available = true
