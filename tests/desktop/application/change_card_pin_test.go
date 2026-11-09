package application_test

import (
	"context"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

type countingChanger struct{ calls int }

func (c *countingChanger) Apply(context.Context, domain.PINChange) error {
	c.calls++
	return nil
}

func TestAMistypedNewPINNeverReachesTheCard(t *testing.T) {
	changer := &countingChanger{}
	use := application.NewChangeCardPIN(changer)

	mistyped := domain.PINChange{Action: domain.ChangePIN, Secret: "1234", NewPIN: "5678", Repeat: "5687"}
	if err := use.Execute(context.Background(), mistyped); err == nil || changer.calls != 0 {
		t.Fatalf("err %v, calls %d: a mismatch must stop before the card", err, changer.calls)
	}
	mistyped.Repeat = "5678"
	if err := use.Execute(context.Background(), mistyped); err != nil || changer.calls != 1 {
		t.Errorf("err %v, calls %d", err, changer.calls)
	}
}
