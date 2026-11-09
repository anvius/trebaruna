package domain_test

import (
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// TestANewPINIsCheckedAgainstTheCardsLimits before the card sees it.
func TestANewPINIsCheckedAgainstTheCardsLimits(t *testing.T) {
	limits := domain.PINLimits{Minimum: 4, Maximum: 8}
	for pin, accepted := range map[string]bool{"": false, "123": false, "1234": true, "12345678": true, "123456789": false} {
		err := limits.Accept(pin)
		if accepted != (err == nil) {
			t.Errorf("%q: %v", pin, err)
		}
		if err != nil && !errors.Is(err, domain.ErrNewPINRejected) {
			t.Errorf("%q: %v is not a rejection", pin, err)
		}
	}
	if err := (domain.PINLimits{}).Accept("1"); err != nil {
		t.Errorf("a card that declares no limits takes any non-empty PIN: %v", err)
	}
}

// TestThePUKStateRanksLikeThePIN.
func TestThePUKStateRanksLikeThePIN(t *testing.T) {
	cases := []struct {
		locked, final, low bool
		want               domain.PINState
	}{
		{false, false, false, domain.PINReady},
		{false, false, true, domain.PINCountLow},
		{false, true, true, domain.PINFinalTry},
		{true, true, true, domain.PINLocked},
	}
	for _, entry := range cases {
		if got := domain.PUKStateOf(entry.locked, entry.final, entry.low); got != entry.want {
			t.Errorf("%+v: %q", entry, got)
		}
	}
}

// TestARefusedPUKStopsTheRun.
func TestARefusedPUKStopsTheRun(t *testing.T) {
	for _, cause := range []error{domain.ErrWrongPUK, domain.ErrPUKLocked, domain.ErrPUKMissing} {
		if !domain.StopsCard(cause) {
			t.Errorf("%v must stop the card", cause)
		}
	}
}

// TestACardNeedsItsModule.
func TestACardNeedsItsModule(t *testing.T) {
	if _, err := domain.NewCard(" ", "DNI"); !errors.Is(err, domain.ErrTokenWithoutModule) {
		t.Errorf("got %v", err)
	}
	card, err := domain.NewCard("/usr/lib/opensc-pkcs11.so", "")
	if err != nil || card.Module() != "/usr/lib/opensc-pkcs11.so" || card.Label() != "" {
		t.Errorf("card %+v, %v", card, err)
	}
}
