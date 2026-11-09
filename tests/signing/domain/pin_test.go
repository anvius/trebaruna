package domain_test

import (
	"errors"
	"fmt"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// TestThePINStateRanksWhatStopsThePerson: a locked card is locked whatever
// else the flags say, and a warning about attempts never hides a PIN that must
// be changed first.
func TestThePINStateRanksWhatStopsThePerson(t *testing.T) {
	ready := domain.PINFlags{Initialized: true, LoginRequired: true}
	cases := []struct {
		name  string
		flags domain.PINFlags
		want  domain.PINState
	}{
		{"ordinary card", ready, domain.PINReady},
		{"a wrong PIN was entered", with(ready, func(f *domain.PINFlags) { f.CountLow = true }), domain.PINCountLow},
		{"one attempt left", with(ready, func(f *domain.PINFlags) { f.CountLow, f.FinalTry = true, true }), domain.PINFinalTry},
		{"locked", with(ready, func(f *domain.PINFlags) { f.Locked, f.FinalTry = true, true }), domain.PINLocked},
		{"PIN to change", with(ready, func(f *domain.PINFlags) { f.ToBeChanged, f.CountLow = true, true }), domain.PINToBeChanged},
		{"no PIN set", domain.PINFlags{LoginRequired: true}, domain.PINNotSet},
		{"no login", domain.PINFlags{Initialized: true}, domain.PINNotRequired},
	}
	for _, entry := range cases {
		if got := domain.PINStateOf(entry.flags); got != entry.want {
			t.Errorf("%s: %q, want %q", entry.name, got, entry.want)
		}
	}
}

func with(flags domain.PINFlags, change func(*domain.PINFlags)) domain.PINFlags {
	change(&flags)
	return flags
}

// TestOnlyAUsableCardCanSign: the window and the command refuse before a PIN
// is spent on a card that cannot sign.
func TestOnlyAUsableCardCanSign(t *testing.T) {
	for state, want := range map[domain.PINState]bool{
		domain.PINReady: true, domain.PINCountLow: true, domain.PINFinalTry: true,
		domain.PINNotRequired: true, domain.PINLocked: false, domain.PINToBeChanged: false,
		domain.PINNotSet: false,
	} {
		if state.CanSign() != want {
			t.Errorf("%q: can sign %t, want %t", state, state.CanSign(), want)
		}
	}
}

// TestARefusalIsKnownBeforeThePIN: the reason a card cannot sign is a
// business error the batch and the window stop on.
func TestARefusalIsKnownBeforeThePIN(t *testing.T) {
	if !errors.Is(domain.PINLocked.Refusal(), domain.ErrCardLocked) {
		t.Error("a locked card must be refused as locked")
	}
	if !errors.Is(domain.PINNotSet.Refusal(), domain.ErrPINExpired) || !domain.StopsCard(domain.PINToBeChanged.Refusal()) {
		t.Error("a PIN to set or to change must be refused and stop the card")
	}
	if domain.PINFinalTry.Refusal() != nil {
		t.Error("a card on its last attempt can still sign")
	}
}

// TestPINErrorsStopTheCard: whatever wraps them, a refused PIN stops every
// further attempt in the run.
func TestPINErrorsStopTheCard(t *testing.T) {
	for _, cause := range []error{domain.ErrWrongPIN, domain.ErrCardLocked, domain.ErrPINExpired, domain.ErrPINMissing} {
		if !domain.StopsCard(fmt.Errorf("signing failed: %w", cause)) {
			t.Errorf("%v must stop the card", cause)
		}
	}
	if domain.StopsCard(errors.New("the reader is gone")) || domain.StopsCard(nil) {
		t.Error("other errors must not stop the card")
	}
}
