package domain_test

import (
	"errors"
	"testing"

	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
)

// TestASavedRecipientIsPickedByFingerprintOrName: the start of the
// fingerprint, colons and case aside, or words of the holder; never a guess
// between two.
func TestASavedRecipientIsPickedByFingerprintOrName(t *testing.T) {
	book := []encryption.SavedRecipient{
		{Holder: "LUCA BIANCHI", Fingerprint: "a1b2c3d4e5"},
		{Holder: "MARIA GARCIA LOPEZ", Fingerprint: "a1f0000000"},
		{Holder: "MARIA ROSSI", Fingerprint: "ffee000000"},
	}
	for wanted, holder := range map[string]string{"A1:B2": "LUCA BIANCHI", "bianchi": "LUCA BIANCHI", "garcia": "MARIA GARCIA LOPEZ", "ffee": "MARIA ROSSI"} {
		if got, err := encryption.Pick(book, wanted); err != nil || got.Holder != holder {
			t.Errorf("%q: %q %v", wanted, got.Holder, err)
		}
	}
	if _, err := encryption.Pick(book, "maria"); !errors.Is(err, encryption.ErrAmbiguousRecipient) {
		t.Errorf("two Marias: %v", err)
	}
	if _, err := encryption.Pick(book, "a1"); !errors.Is(err, encryption.ErrAmbiguousRecipient) {
		t.Errorf("two fingerprints starting a1: %v", err)
	}
	for _, wanted := range []string{"verdi", "", "  "} {
		if _, err := encryption.Pick(book, wanted); !errors.Is(err, encryption.ErrNoSavedRecipient) {
			t.Errorf("%q: %v", wanted, err)
		}
	}
}
