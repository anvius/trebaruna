package domain_test

import (
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

func TestAPINChangeIsCheckedBeforeTheCard(t *testing.T) {
	cases := []struct {
		change domain.PINChange
		want   domain.ProblemCode
	}{
		{domain.PINChange{Action: domain.ChangePIN, NewPIN: "5678", Repeat: "5678"}, domain.ProblemMissingPIN},
		{domain.PINChange{Action: domain.UnlockPIN, NewPIN: "5678", Repeat: "5678"}, domain.ProblemMissingPUK},
		{domain.PINChange{Action: domain.ChangePIN, Secret: "1234"}, domain.ProblemNewPINRejected},
		{domain.PINChange{Action: domain.ChangePIN, Secret: "1234", NewPIN: "5678", Repeat: "5679"}, domain.ProblemPINMismatch},
	}
	for _, entry := range cases {
		var problem domain.Problem
		if err := entry.change.Validate(); !errors.As(err, &problem) || problem.Code != entry.want {
			t.Errorf("%+v: %v, want %s", entry.change, err, entry.want)
		}
	}
	complete := domain.PINChange{Action: domain.UnlockPIN, Secret: "87654321", NewPIN: "2468", Repeat: "2468"}
	if err := complete.Validate(); err != nil {
		t.Errorf("a complete unlock must pass: %v", err)
	}
}
