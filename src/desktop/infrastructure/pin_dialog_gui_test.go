//go:build gui

package infrastructure

import (
	"context"
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// scriptedPINChanger records the changes and answers with err.
type scriptedPINChanger struct {
	changes []domain.PINChange
	err     error
}

func (s *scriptedPINChanger) Apply(_ context.Context, change domain.PINChange) error {
	s.changes = append(s.changes, change)
	return s.err
}

func pinFixture(t *testing.T, changer *scriptedPINChanger) formFixture {
	t.Helper()
	cards := &scriptedCards{listings: [][]domain.CardCertificate{identityCard(signing.PINReady)}}
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, cards)
	fixture.desktop.pinChange = application.NewChangeCardPIN(changer)
	return fixture
}

func TestThePINIsChangedForTheCardChosen(t *testing.T) {
	changer := &scriptedPINChanger{}
	fixture := pinFixture(t, changer)
	chooseCard(t, fixture.desktop.form)

	dialog := fixture.desktop.showPINDialog(domain.ChangePIN)
	if dialog.token != "DNI electrónico" {
		t.Errorf("token %q: the card chosen in the form is the one changed", dialog.token)
	}
	dialog.secret.SetText("1234")
	dialog.newPIN.SetText("5678")
	dialog.repeat.SetText("5678")
	test.Tap(dialog.apply)

	if len(changer.changes) != 1 || changer.changes[0].Secret != "1234" || changer.changes[0].NewPIN != "5678" ||
		changer.changes[0].Action != domain.ChangePIN {
		t.Fatalf("changes %+v", changer.changes)
	}
	if !dialog.closed {
		t.Error("a successful change closes the dialog")
	}
}

func TestAMistypedNewPINStaysInTheDialog(t *testing.T) {
	changer := &scriptedPINChanger{}
	fixture := pinFixture(t, changer)

	dialog := fixture.desktop.showPINDialog(domain.ChangePIN)
	dialog.secret.SetText("1234")
	dialog.newPIN.SetText("5678")
	dialog.repeat.SetText("5687")
	test.Tap(dialog.apply)

	if len(changer.changes) != 0 || dialog.status.Text != fixture.desktop.messages.PINMismatch || dialog.closed {
		t.Errorf("status %q, changes %d: a mismatch is said in the dialog, the card is not asked", dialog.status.Text, len(changer.changes))
	}
	if dialog.token != "" {
		t.Errorf("token %q: without a card chosen, the only card present is meant", dialog.token)
	}
}

func TestARefusedPUKIsClearedAndExplained(t *testing.T) {
	changer := &scriptedPINChanger{err: domain.Problem{Code: domain.ProblemWrongPUK, Detail: string(signing.PINFinalTry)}}
	fixture := pinFixture(t, changer)

	dialog := fixture.desktop.showPINDialog(domain.UnlockPIN)
	dialog.secret.SetText("00000000")
	dialog.newPIN.SetText("2468")
	dialog.repeat.SetText("2468")
	test.Tap(dialog.apply)

	m := fixture.desktop.messages
	if dialog.status.Text != m.WrongPUKFinalTry || dialog.status.Importance != widget.DangerImportance {
		t.Errorf("status %q: the refusal and the last attempt must be said", dialog.status.Text)
	}
	if dialog.secret.Text != "" || dialog.closed {
		t.Error("a refused PUK is cleared and the dialog stays open")
	}
}

// TestThePUKDialogAsksForTheCurrentAndTheNewPUK, and says so when done.
func TestThePUKDialogAsksForTheCurrentAndTheNewPUK(t *testing.T) {
	changer := &scriptedPINChanger{}
	fixture := pinFixture(t, changer)
	m := fixture.desktop.messages

	dialog := fixture.desktop.showPINDialog(domain.ChangePUK)
	dialog.secret.SetText("87654321")
	dialog.newPIN.SetText("11223344")
	dialog.repeat.SetText("11223344")
	if dialog.apply.Text != m.ChangePUKButton {
		t.Errorf("button %q", dialog.apply.Text)
	}
	test.Tap(dialog.apply)
	if len(changer.changes) != 1 || changer.changes[0].Action != domain.ChangePUK || changer.changes[0].NewPIN != "11223344" || !dialog.closed {
		t.Errorf("changes %+v, closed %t", changer.changes, dialog.closed)
	}
}
