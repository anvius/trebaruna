//go:build cgo

package infrastructure

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

// inspectToken lists the slots and certificates a PKCS#11 module exposes.
//
// The module is reached through miekg/pkcs11 directly rather than through
// crypto11, because crypto11 answers one question — "give me the key for this
// label" — and a diagnostic needs a different one: "what is actually there".
//
// The token is not logged in. Reading the public certificate objects does not
// need a PIN on any card that follows the profile, and a diagnostic that
// demands the PIN before it says anything is a diagnostic that cannot be run
// without the thing it is diagnosing.
func inspectToken(module, pin string) ([]TokenSlot, error) {
	if module == "" {
		return nil, fmt.Errorf("no PKCS#11 module given: use --module <path>")
	}

	context := pkcs11.New(module)
	if context == nil {
		return nil, fmt.Errorf("cannot load the PKCS#11 module %s", module)
	}
	defer context.Destroy()

	// Initialising a module that is already initialised is not an error worth
	// stopping for. Several drivers are process-wide singletons: the first
	// caller initialises them and every later caller is told the module is
	// already up. Refusing to work in that case would make the diagnostic
	// unusable in exactly the situation it exists for — a program that already
	// talks to the card.
	initialised := true
	if err := context.Initialize(); err != nil {
		if !alreadyInitialised(err) {
			return nil, fmt.Errorf(
				"cannot initialise the PKCS#11 module %s: %w\n"+
					"  check: the path exists, the reader is connected, and pcscd is running",
				module, err)
		}
		// The module was already up. Finalising it here would take it down for
		// whoever else is using it.
		initialised = false
	}
	if initialised {
		defer context.Finalize()
	}

	slots, err := context.GetSlotList(false)
	if err != nil {
		return nil, fmt.Errorf("cannot list the slots of %s: %w", module, err)
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
		entry.Certificates = readCertificates(context, slot, pin)

		result = append(result, entry)
	}

	return result, nil
}

// alreadyInitialised reports whether the error says the module was already up.
//
// The code is CKR_CRYPTOKI_ALREADY_INITIALIZED, 0x00000191. It is checked by
// number because the constant is not exported by the PKCS#11 binding.
func alreadyInitialised(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "0x191")
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
			parsed, err := x509.ParseCertificate(value)
			if err != nil {
				continue
			}
			certificates = append(certificates, describeCertificate(parsed))
		}
	}

	return certificates
}
