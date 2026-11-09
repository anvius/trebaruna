//go:build gui

package infrastructure

// Acceptance tests for the card source of the signing form, with the cards in
// the readers and the signer scripted.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// scriptedCards answers each listing with the next state, repeating the last.
type scriptedCards struct {
	mutex    sync.Mutex
	listings [][]domain.CardCertificate
	err      error
	calls    int
}

func (s *scriptedCards) Cards(context.Context) ([]domain.CardCertificate, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.calls++
	if s.err != nil || len(s.listings) == 0 {
		return nil, s.err
	}
	listing := s.listings[min(s.calls, len(s.listings))-1]
	return append([]domain.CardCertificate{}, listing...), nil
}

func (s *scriptedCards) callCount() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.calls
}

// identityCard is a DNIe: an authentication and a signature certificate.
func identityCard(state signing.PINState) []domain.CardCertificate {
	holder := func(name string, qualified bool) domain.CertificateSummary {
		return domain.CertificateSummary{
			Holder: name, Identifier: "IDCES-00000000T", Issuer: "DIRECCION GENERAL DE LA POLICIA",
			NotAfter: time.Now().Add(900 * 24 * time.Hour), Trusted: true, Qualified: qualified, Locality: "Madrid",
		}
	}
	return []domain.CardCertificate{
		{Token: "DNI electrónico", Reader: "Lector 1", PIN: state, Fingerprint: "a18a8855", Serial: "1002",
			SignsByDefault: true, Summary: holder("MARIA GARCIA (FIRMA)", true)},
		{Token: "DNI electrónico", Reader: "Lector 1", PIN: state, Fingerprint: "40be7f7a", Serial: "1001",
			Summary: holder("MARIA GARCIA (AUTENTICACION)", false)},
	}
}

func chooseCard(t *testing.T, form *signForm) {
	t.Helper()
	form.keySource.SetSelected(form.m.KeyFromCard)
	settle(t, func() bool { return form.summary != nil || form.standing.Text == form.m.NoCards })
}

func TestACardOffersItsSigningCertificate(t *testing.T) {
	cards := &scriptedCards{listings: [][]domain.CardCertificate{identityCard(signing.PINReady)}}
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, cards)
	form := fixture.desktop.form

	chooseCard(t, form)

	if form.fileSource.Visible() || !form.cards.object().Visible() {
		t.Error("the card half must replace the file half")
	}
	if form.holder.Text != "MARIA GARCIA (FIRMA)" || form.standing.Importance != widget.SuccessImportance {
		t.Errorf("holder %q (%v): the signing certificate must be chosen and shown", form.holder.Text, form.standing.Importance)
	}
	if form.cards.choice.Selected != "MARIA GARCIA (FIRMA)" || len(form.cards.choice.Options) != 2 {
		t.Errorf("selected %q of %v", form.cards.choice.Selected, form.cards.choice.Options)
	}
	if form.cards.where.Text != "En la tarjeta «DNI electrónico», Lector 1." {
		t.Errorf("where = %q: the card and the reader must be named", form.cards.where.Text)
	}
	if form.cards.pin.Disabled() || form.cards.note.Visible() {
		t.Error("a ready card asks for its PIN and has nothing to warn about")
	}
	if fixture.desktop.pages.identity.Name != "MARIA GARCIA (FIRMA)" {
		t.Error("the seal must print the card's holder")
	}
	preferences := fyne.CurrentApp().Preferences()
	if preferences.String(preferenceKeySource) != "card" || preferences.String(preferenceCardCertificate) != "a18a8855" {
		t.Error("the card and its certificate must be remembered, never the PIN")
	}
}

func TestSigningWithACardSendsTheChosenCertificateAndThePIN(t *testing.T) {
	cards := &scriptedCards{listings: [][]domain.CardCertificate{identityCard(signing.PINReady)}}
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, cards)
	form := fixture.desktop.form
	form.setDocument("/tmp/offerta.docx")
	chooseCard(t, form)

	form.cards.choice.SetSelected(form.cards.choice.Options[1])
	form.cards.pin.SetText("123456")
	test.Tap(form.signButton)

	intent := <-fixture.signer.intents
	// The report is the signing goroutine's last word; the test ends after it,
	// so no widget changes under the next test.
	settle(t, func() bool { return form.afterSign.Visible() })
	if intent.Card.Fingerprint != "40be7f7a" || intent.Card.Token != "DNI electrónico" || intent.Card.PIN != "123456" {
		t.Errorf("card key %+v: the certificate picked and its PIN must be sent", intent.Card)
	}
	if intent.Key.Path != "" {
		t.Errorf("no certificate file must travel with a card: %q", intent.Key.Path)
	}
}

func TestALockedCardIsStatedAndNotTried(t *testing.T) {
	cards := &scriptedCards{listings: [][]domain.CardCertificate{identityCard(signing.PINLocked)}}
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, cards)
	form := fixture.desktop.form
	form.setDocument("/tmp/offerta.docx")
	chooseCard(t, form)

	if form.cards.note.Text != form.m.CardLocked || !form.cards.pin.Disabled() {
		t.Errorf("note %q, PIN enabled %t: a locked card must say so and take no PIN", form.cards.note.Text, !form.cards.pin.Disabled())
	}
	test.Tap(form.signButton)
	if form.status.Text != form.m.CardLocked || len(fixture.signer.intents) != 0 {
		t.Errorf("status %q: a locked card must stop before the signer runs", form.status.Text)
	}
}

func TestAMissingPINStopsBeforeTheCardSeesIt(t *testing.T) {
	cards := &scriptedCards{listings: [][]domain.CardCertificate{identityCard(signing.PINReady)}}
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, cards)
	form := fixture.desktop.form
	form.setDocument("/tmp/offerta.docx")
	chooseCard(t, form)

	test.Tap(form.signButton)
	if form.status.Text != form.m.MissingPIN || len(fixture.signer.intents) != 0 {
		t.Errorf("status %q: an empty PIN must never reach the card", form.status.Text)
	}
}

func TestAWrongPINIsClearedAndTheCardReadAgain(t *testing.T) {
	cards := &scriptedCards{listings: [][]domain.CardCertificate{
		identityCard(signing.PINReady), identityCard(signing.PINFinalTry),
	}}
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, cards)
	fixture.desktop.application = application.NewSignFromDesktop(capturingSigner{
		intents: fixture.signer.intents,
		err:     domain.Problem{Code: domain.ProblemWrongPIN, Detail: string(signing.PINFinalTry)},
	}, func(string) bool { return true })
	form := fixture.desktop.form
	form.signing = fixture.desktop.application
	form.setDocument("/tmp/offerta.docx")
	chooseCard(t, form)

	form.cards.pin.SetText("000000")
	test.Tap(form.signButton)
	<-fixture.signer.intents
	settle(t, func() bool {
		return cards.callCount() == 2 && form.summary != nil && form.cards.note.Text == form.m.PINFinalTry
	})

	if form.status.Text != form.m.WrongPINFinalTry || form.status.Importance != widget.DangerImportance {
		t.Errorf("status %q: the refusal and the attempt left must be said", form.status.Text)
	}
	if form.cards.pin.Text != "" {
		t.Error("a refused PIN must be cleared, not offered for another try")
	}
}

func TestABatchStopsAtTheFirstRefusedPIN(t *testing.T) {
	cards := &scriptedCards{listings: [][]domain.CardCertificate{identityCard(signing.PINReady)}}
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, cards)
	intents := make(chan domain.SigningIntent, 3)
	fixture.desktop.form.signing = application.NewSignFromDesktop(capturingSigner{
		intents: intents, err: domain.Problem{Code: domain.ProblemWrongPIN},
	}, func(string) bool { return true })
	form := fixture.desktop.form
	form.setDocuments([]string{"/tmp/uno.txt", "/tmp/due.txt", "/tmp/tre.txt"})
	chooseCard(t, form)

	form.cards.pin.SetText("000000")
	test.Tap(form.signButton)
	// The refusal also reads the cards again; wait for that listing too.
	settle(t, func() bool {
		return strings.Contains(form.status.Text, form.m.BatchNotTried) &&
			cards.callCount() == 2 && !form.cards.search.Disabled() && form.summary != nil
	})

	if len(intents) != 1 {
		t.Errorf("%d signatures attempted: a refused PIN must not be tried on the next documents", len(intents))
	}
	if strings.Count(form.status.Text, form.m.BatchNotTried) != 2 {
		t.Errorf("status %q: the two remaining documents must be reported as not tried", form.status.Text)
	}
}

// TestTwoCertificatesOfOneHolderSayWhichSigns: an Italian card names its
// holder the same way on the authentication and the signature certificate.
func TestTwoCertificatesOfOneHolderSayWhichSigns(t *testing.T) {
	card := identityCard(signing.PINReady)
	card[0].Summary.Holder, card[1].Summary.Holder = "MARIO ROSSI", "MARIO ROSSI"
	cards := &scriptedCards{listings: [][]domain.CardCertificate{card}}
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, cards)
	form := fixture.desktop.form
	chooseCard(t, form)

	want := []string{"MARIO ROSSI (para firmar)", "MARIO ROSSI (otro uso)"}
	if strings.Join(form.cards.choice.Options, "|") != strings.Join(want, "|") || form.cards.choice.Selected != want[0] {
		t.Errorf("options %v, selected %q", form.cards.choice.Options, form.cards.choice.Selected)
	}
}

func TestNoCardSaysWhatToDo(t *testing.T) {
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, &scriptedCards{})
	form := fixture.desktop.form

	chooseCard(t, form)
	if form.standing.Text != form.m.NoCards || form.standing.Importance != widget.MediumImportance {
		t.Errorf("standing %q (%v): an empty reader is an instruction, not an alarm", form.standing.Text, form.standing.Importance)
	}
}

func TestChoosingAFileLeavesTheCard(t *testing.T) {
	cards := &scriptedCards{listings: [][]domain.CardCertificate{identityCard(signing.PINReady)}}
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, cards)
	form := fixture.desktop.form
	chooseCard(t, form)

	form.setCertificate("/tmp/rossi.p12")
	settle(t, func() bool { return form.summary != nil && form.summary.Holder == "MARIO ROSSI" })
	if form.keySource.Selected != form.m.KeyFromFile || !form.fileSource.Visible() || form.cards.object().Visible() {
		t.Error("choosing a certificate file must switch the step back to the file")
	}
}
