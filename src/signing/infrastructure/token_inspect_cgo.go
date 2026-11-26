//go:build cgo

package infrastructure

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/pkcs11"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
)

// inspectToken lists the slots and certificates a PKCS#11 module exposes.
//
// The module is reached through the same plain binding the signatures use;
// the diagnostic asks "what is actually there", before any login.
//
// The token is not logged in. Reading the public certificate objects does not
// need a PIN on any card that follows the profile, and a diagnostic that
// demands the PIN before it says anything is a diagnostic that cannot be run
// without the thing it is diagnosing.
func inspectToken(path, parameters, pin string) ([]TokenSlot, error) {
	loaded, err := loadModule(path, parameters)
	if err != nil {
		return nil, err
	}
	defer loaded.unload()
	context := loaded.context

	slots, err := context.GetSlotList(false)
	if err != nil {
		return nil, fmt.Errorf("cannot list the slots of %s: %w", path, err)
	}

	result := make([]TokenSlot, 0, len(slots))
	for _, slot := range slots {
		entry := TokenSlot{Index: int(slot)}

		if info, err := context.GetSlotInfo(slot); err == nil {
			entry.Description = strings.TrimSpace(info.SlotDescription)
			if entry.Description == "" {
				entry.Description = strings.TrimSpace(info.ManufacturerID)
			}
		}

		token, err := context.GetTokenInfo(slot)
		if err != nil {
			// An empty reader reports an error here rather than an empty label.
			// That is the normal case of "the reader is there, the card is not",
			// and saying so is more useful than skipping the slot.
			result = append(result, entry)
			continue
		}

		entry.TokenLabel = strings.TrimSpace(token.Label)
		entry.TokenSerial = strings.TrimSpace(token.SerialNumber)
		entry.Manufacturer = strings.TrimSpace(token.ManufacturerID)
		entry.LoginState = describeLoginState(token)
		entry.PINState = domain.PINStateOf(domain.PINFlags{
			Initialized:   token.Flags&pkcs11.CKF_USER_PIN_INITIALIZED != 0,
			LoginRequired: token.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0,
			CountLow:      token.Flags&pkcs11.CKF_USER_PIN_COUNT_LOW != 0,
			FinalTry:      token.Flags&pkcs11.CKF_USER_PIN_FINAL_TRY != 0,
			Locked:        token.Flags&pkcs11.CKF_USER_PIN_LOCKED != 0,
			ToBeChanged:   token.Flags&pkcs11.CKF_USER_PIN_TO_BE_CHANGED != 0,
		})
		entry.PINPad = token.Flags&pkcs11.CKF_PROTECTED_AUTHENTICATION_PATH != 0
		entry.PUKState = domain.PUKStateOf(token.Flags&pkcs11.CKF_SO_PIN_LOCKED != 0,
			token.Flags&pkcs11.CKF_SO_PIN_FINAL_TRY != 0, token.Flags&pkcs11.CKF_SO_PIN_COUNT_LOW != 0)
		entry.Limits = pinLimits(token)
		entry.Certificates, entry.Keyed = readCertificates(context, slot, pin)
		markDefault(entry.Certificates)

		result = append(result, entry)
	}

	return result, nil
}

// pinLimits reads the PIN lengths a token declares. A token that does not
// know says so with an absurd maximum, which counts as no limit.
func pinLimits(token pkcs11.TokenInfo) domain.PINLimits {
	limits := domain.PINLimits{Minimum: int(token.MinPinLen), Maximum: int(token.MaxPinLen)}
	if token.MaxPinLen > 1024 {
		limits.Maximum = 0
	}
	if token.MinPinLen > 1024 {
		limits.Minimum = 0
	}
	return limits
}

// describeLoginState renders the login state of a token.
//
// The states are ordered by how much they stop the user: a locked PIN cannot
// be worked around, a PIN that must be changed can, and a token that only needs
// a PIN is the ordinary case.
func describeLoginState(token pkcs11.TokenInfo) string {
	switch {
	case token.Flags&pkcs11.CKF_USER_PIN_LOCKED != 0:
		return "user PIN locked"
	case token.Flags&pkcs11.CKF_USER_PIN_TO_BE_CHANGED != 0:
		return "user PIN must be changed"
	case token.Flags&pkcs11.CKF_USER_PIN_INITIALIZED == 0:
		return "user PIN not set"
	case token.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0:
		return "login required"
	default:
		return "public"
	}
}

// readCertificates lists the certificates the token holds with their private
// keys. The first result is those usable for signing (see
// domain.UsableForSigning); the second is every one with its key, whatever its
// usage, which is what an envelope is opened with. A certificate whose key is
// not on the token is listed by neither.
//
// The certificate objects are public: reading them needs no PIN on any card
// that follows the profile. When a PIN is given, the session is opened for
// reading anyway, because some drivers refuse the public objects on a
// protected session.
func readCertificates(context *pkcs11.Ctx, slot uint, pin string) (signing, keyed []TokenCertificate) {
	session, err := context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		// A read-only session is enough for the public objects.
		session, err = context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	}
	if err != nil {
		return nil, nil
	}
	defer context.CloseSession(session)

	if pin != "" {
		// A wrong PIN is not an error worth reporting: the public objects are
		// still readable, and the point of the diagnostic is to show what is
		// there.
		_ = context.Login(session, pkcs11.CKU_USER, pin)
		defer context.Logout(session)
	}

	// The template carries the class only. Adding CKA_ID with a nil value does
	// not act as a wildcard: the driver reads it as "the identifier is empty"
	// and matches nothing, which hides every certificate on the card.
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	keys, keysKnown := privateKeyIdentifiers(context, slot, session, pin != "")
	now := time.Now()

	if err := context.FindObjectsInit(session, template); err != nil {
		return nil, nil
	}

	for {
		handles, _, err := context.FindObjects(session, 10)
		if err != nil {
			break
		}
		if len(handles) == 0 {
			break
		}
		for _, handle := range handles {
			attributes, err := context.GetAttributeValue(session, handle,
				[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, nil), pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
			if err != nil || len(attributes) < 2 {
				continue
			}
			identifier, value := attributes[0].Value, attributes[1].Value
			if len(value) == 0 || (keysKnown && !keys[string(identifier)]) {
				continue
			}
			parsed, err := brainpool.ParseCertificate(value)
			if err != nil {
				continue
			}
			described := describeCertificate(parsed)
			keyed = append(keyed, described)
			if domain.UsableForSigning(parsed, now) {
				signing = append(signing, described)
			}
		}
	}

	return signing, keyed
}

// privateKeyIdentifiers lists the identifiers (CKA_ID) of the private keys
// the session can see. A certificate pairs with a key by its identifier, as
// signing pairs them (Pairs).
//
// The second result says whether the list means anything. A token that needs
// a login hides its private keys from a session that has not logged in (a
// Firefox store with a primary password, or a card that keeps its keys behind
// the PIN), so an empty list there says nothing: the keys are not known to be
// absent, and the certificates are judged by their own rules alone.
func privateKeyIdentifiers(context *pkcs11.Ctx, slot uint, session pkcs11.SessionHandle, loggedIn bool) (map[string]bool, bool) {
	identifiers := map[string]bool{}
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}
	if err := context.FindObjectsInit(session, template); err != nil {
		return identifiers, false
	}
	defer context.FindObjectsFinal(session)

	for {
		handles, _, err := context.FindObjects(session, 10)
		if err != nil || len(handles) == 0 {
			break
		}
		for _, handle := range handles {
			attributes, err := context.GetAttributeValue(session, handle,
				[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, nil)})
			if err != nil || len(attributes) == 0 || len(attributes[0].Value) == 0 {
				continue
			}
			identifiers[string(attributes[0].Value)] = true
		}
	}

	loginRequired := true
	if info, err := context.GetTokenInfo(slot); err == nil {
		loginRequired = info.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0
	}
	known := len(identifiers) > 0 || !loginRequired || loggedIn
	return identifiers, known
}
