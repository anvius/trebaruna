//go:build cgo

package infrastructure

import (
	"fmt"
	"strings"

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
		entry.Certificates = readCertificates(context, slot, pin)
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

// readCertificates lists the certificates the token holds.
//
// The certificate objects are public: reading them needs no PIN on any card
// that follows the profile. When a PIN is given, the session is opened for
// reading anyway, because some drivers refuse the public objects on a
// protected session.
func readCertificates(context *pkcs11.Ctx, slot uint, pin string) []TokenCertificate {
	session, err := context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		// A read-only session is enough for the public objects.
		session, err = context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	}
	if err != nil {
		return nil
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

	if err := context.FindObjectsInit(session, template); err != nil {
		return nil
	}

	var certificates []TokenCertificate
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
				[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
			if err != nil || len(attributes) == 0 {
				continue
			}
			value := attributes[0].Value
			if len(value) == 0 {
				continue
			}
			parsed, err := brainpool.ParseCertificate(value)
			if err != nil {
				continue
			}
			certificates = append(certificates, describeCertificate(parsed))
		}
	}

	return certificates
}
