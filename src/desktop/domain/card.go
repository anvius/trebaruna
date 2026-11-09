package domain

import (
	"errors"

	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// CardCertificate is a certificate held by a card in a reader, as the window
// offers it: who it names and whether the card can sign with it now.
type CardCertificate struct {
	// Token is the label of the card; Reader names the slot it sits in.
	Token  string
	Reader string
	// PIN is what the card says about its PIN before anyone types it.
	PIN    signing.PINState
	PINPad bool
	// Fingerprint (SHA-256) names the certificate to sign with.
	Fingerprint string
	Serial      string
	// SignsByDefault marks the certificate the card signs with when the person
	// names none: the only one, or the only one with non-repudiation.
	SignsByDefault bool
	Summary        CertificateSummary
}

// Key is the certificate on the card chosen to sign, with the PIN that opens
// it. The PIN travels to the signer in its environment, never on a command
// line (ADR-0006).
func (c CardCertificate) Key(pin string) CardKey {
	return CardKey{Token: c.Token, Fingerprint: c.Fingerprint, PIN: pin, PINPad: c.PINPad, State: c.PIN}
}

// CardKey is a certificate on a card and the PIN typed for it.
type CardKey struct {
	Token       string
	Fingerprint string
	PIN         string
	PINPad      bool
	State       signing.PINState
}

// Chosen reports whether a card certificate was chosen at all.
func (k CardKey) Chosen() bool { return k.Fingerprint != "" }

// problem is what stops this card from signing before anything is spawned:
// a card that cannot sign in its state, or a PIN not typed for a card that
// takes it from the keyboard.
func (k CardKey) problem() error {
	if refusal := k.State.Refusal(); refusal != nil {
		if errors.Is(refusal, signing.ErrCardLocked) {
			return Problem{Code: ProblemCardLocked}
		}
		return Problem{Code: ProblemPINExpired}
	}
	if k.PIN == "" && !k.PINPad && k.State != signing.PINNotRequired {
		return Problem{Code: ProblemMissingPIN}
	}
	return nil
}
