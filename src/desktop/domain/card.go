package domain

import (
	"errors"
	"strings"

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
	// Store names the software store the certificate lives in ("firefox"),
	// or the remote service ("csc"); empty for a card.
	Store string
	// Credential is the remote service's credential the certificate is
	// the key of; empty elsewhere.
	Credential string
}

// Key is the certificate on the card chosen to sign, with the PIN that opens
// it. The PIN travels to the signer in its environment, never on a command
// line (ADR-0006).
func (c CardCertificate) Key(pin string) CardKey {
	return CardKey{Token: c.Token, Fingerprint: c.Fingerprint, PIN: pin, PINPad: c.PINPad, State: c.PIN, Store: c.Store,
		Credential: c.Credential}
}

// CardKey is a certificate on a card and the PIN typed for it.
type CardKey struct {
	Token       string
	Fingerprint string
	PIN         string
	PINPad      bool
	State       signing.PINState
	Store       string
	// Credential and Account say, for a remote key, which credential and
	// how to reach the service.
	Credential string
	Account    RemoteAccount
}

// StoreFirefox is the Firefox certificate store, used in place.
const StoreFirefox = "firefox"

// StoreRemote is a remote signing service (CSC): its credentials are
// listed and chosen as a card's certificates.
const StoreRemote = "csc"

// RemoteAccount is how to reach a remote signing service: its address, and
// a user and password, or the client id of a sign-in in the browser. OTP is
// the one-time password a credential may ask for each signature. The
// secrets travel to the command in its environment.
type RemoteAccount struct {
	Address     string
	User        string
	Password    string
	OAuthClient string
	OTP         string
}

// Chosen reports whether a card certificate was chosen at all.
func (k CardKey) Chosen() bool { return k.Fingerprint != "" }

// problem is what stops this card from signing before anything is spawned:
// a card that cannot sign in its state, or a PIN not typed for a card that
// takes it from the keyboard.
func (k CardKey) problem() error {
	if k.Store == StoreRemote && strings.TrimSpace(k.Account.Address) == "" {
		return Problem{Code: ProblemMissingService}
	}
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
