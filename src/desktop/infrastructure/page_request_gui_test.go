//go:build gui

package infrastructure

import (
	"context"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// scriptedSession plays the command's side.
type scriptedSession struct {
	steps     []domain.PageStep
	decisions []domain.PageDecision
	closed    bool
}

func (s *scriptedSession) Next() (domain.PageStep, error) {
	step := s.steps[0]
	s.steps = s.steps[1:]
	return step, nil
}
func (s *scriptedSession) Decide(decision domain.PageDecision) error {
	s.decisions = append(s.decisions, decision)
	return nil
}
func (s *scriptedSession) Close() error { s.closed = true; return nil }

type scriptedRequests struct{ session *scriptedSession }

func (r scriptedRequests) Open(context.Context, string) (application.PageSession, error) {
	return r.session, nil
}

func signProposal() domain.PageProposal {
	return domain.PageProposal{Operation: "sign", Site: "sede.example", AppName: "SistemaRED", Format: "CAdES",
		DataSize: 4, DataSHA256: "b221d9db", Filters: []string{"subject.rfc2254:(cn=MARIA*)"},
		Policy: "AGE 1.9", Roles: []string{"Apoderado"}, Place: "Sevilla, ES",
		Warnings: []string{"the answer travels to the site encrypted with single DES and an 8-digit key: anyone who sees it can read it"}}
}

func proposalStep(proposal domain.PageProposal) domain.PageStep {
	return domain.PageStep{Proposal: &proposal}
}

func outcomeStep(answer string) domain.PageStep {
	return domain.PageStep{Outcome: &domain.PageOutcome{Answer: answer, Delivered: true}}
}

func pageFixture(t *testing.T, steps ...domain.PageStep) (*pageRequest, *scriptedSession) {
	t.Helper()
	test.NewTempApp(t)
	InstallTranslations(messaging.Spanish)
	window := test.NewTempWindow(t, nil)
	session := &scriptedSession{steps: steps}
	cards := application.NewListCards(&scriptedCards{listings: [][]domain.CardCertificate{identityCard(signing.PINReady)}})
	request := newPageRequest(window, messaging.For(messaging.Spanish),
		application.NewReviewPageRequest(scriptedRequests{session: session}), cards, cards)
	request.run, request.cards.run = inLine, inLine
	window.SetContent(request.object())
	window.Resize(fyne.NewSize(640, 720))
	request.start("afirma://sign?x=1")
	return request, session
}

func detailText(request *pageRequest) string {
	var texts []string
	for _, object := range request.details.Objects {
		if label, ok := object.(*widget.Label); ok {
			texts = append(texts, label.Text)
		}
	}
	return strings.Join(texts, "\n")
}

func TestThePageRequestIsShownBeforeAnything(t *testing.T) {
	request, session := pageFixture(t, proposalStep(signProposal()))
	text := detailText(request)
	for _, shown := range []string{"Una página web pide tu firma", "Firmar un documento", "sede.example", "SistemaRED",
		"4 bytes", "subject.rfc2254:(cn=MARIA*)", "DES simple",
		"La firma declarará la política AGE 1.9", "el rol Apoderado", "el lugar Sevilla, ES"} {
		if !strings.Contains(text, shown) {
			t.Errorf("the request must show %q:\n%s", shown, text)
		}
	}
	if len(session.decisions) != 0 || request.approve.Disabled() {
		t.Error("nothing is decided before the person presses a button")
	}
	if request.keySource.Selected != request.m.KeyFromCard || !strings.Contains(request.cards.choice.Selected, "MARIA GARCIA") {
		t.Errorf("the card is the default source, with its signing certificate chosen: %q", request.cards.choice.Selected)
	}
}

func TestApprovingWithACardSendsItsCertificateAndPIN(t *testing.T) {
	request, session := pageFixture(t, proposalStep(signProposal()), outcomeStep("Y2VydA==|c2ln"))
	request.cards.pin.SetText("123456")
	test.Tap(request.approve)

	if len(session.decisions) != 1 || !session.decisions[0].Approved || session.decisions[0].Card.Fingerprint != "a18a8855" ||
		session.decisions[0].Card.PIN != "123456" {
		t.Fatalf("decisions %+v", session.decisions)
	}
	if request.status.Text != "Hecho: la respuesta ha llegado a sede.example." || !request.closing.Visible() || request.approve.Visible() {
		t.Errorf("status %q", request.status.Text)
	}
	if !session.closed {
		t.Error("the session ends with the outcome")
	}
}

func TestApprovingWithAFileSendsTheKeyAndPassphrase(t *testing.T) {
	request, session := pageFixture(t, proposalStep(signProposal()), outcomeStep("Y2VydA==|c2ln"))
	request.keySource.SetSelected(request.m.KeyFromFile)
	request.keyFile = "/home/maria/maria.p12"
	request.passphrase.SetText("segreto")
	test.Tap(request.approve)
	if len(session.decisions) != 1 || session.decisions[0].KeyFile.Path != "/home/maria/maria.p12" || session.decisions[0].KeyFile.Passphrase != "segreto" {
		t.Fatalf("decisions %+v", session.decisions)
	}
}

func TestARefusedCertificateIsSaidAndAskedAgain(t *testing.T) {
	rejected := signProposal()
	rejected.Rejected = "LUCA BIANCHI is not a certificate this page accepts"
	request, session := pageFixture(t, proposalStep(signProposal()), proposalStep(rejected), outcomeStep("Y2VydA==|c2ln"))
	request.cards.pin.SetText("123456")
	test.Tap(request.approve)
	if !strings.HasPrefix(request.status.Text, "La página no acepta ese certificado") || request.approve.Disabled() {
		t.Fatalf("status %q", request.status.Text)
	}
	test.Tap(request.approve)
	if len(session.decisions) != 2 || !request.closing.Visible() {
		t.Errorf("decisions %d", len(session.decisions))
	}
}

func TestDecliningTellsThePage(t *testing.T) {
	request, session := pageFixture(t, proposalStep(signProposal()), outcomeStep("CANCEL"))
	test.Tap(request.decline)
	if len(session.decisions) != 1 || session.decisions[0].Approved || request.status.Text != request.m.PageDeclined {
		t.Errorf("decisions %+v, status %q", session.decisions, request.status.Text)
	}
}

func TestASaveNeedsAPlaceBeforeAnythingIsSent(t *testing.T) {
	save := domain.PageProposal{Operation: "save", Site: "sede.example", DataSize: 10, DataSHA256: "ab", SuggestedName: "justificante.pdf"}
	request, session := pageFixture(t, proposalStep(save))
	if request.keyBox.Visible() || !request.saveRow.object().Visible() || request.approve.Text != request.m.PageApproveSave {
		t.Error("saving needs no certificate, only a place")
	}
	test.Tap(request.approve)
	if len(session.decisions) != 0 || request.status.Text != request.m.MissingSaveTo {
		t.Errorf("status %q, decisions %d", request.status.Text, len(session.decisions))
	}
}

func TestAFailureIsSaid(t *testing.T) {
	request, _ := pageFixture(t, domain.PageStep{Outcome: &domain.PageOutcome{Answer: "SAF_06: Formato de firma no soportado", Error: "SAF_06: Formato de firma no soportado"}})
	if !strings.Contains(request.status.Text, "SAF_06") || request.status.Importance != widget.DangerImportance {
		t.Errorf("status %q", request.status.Text)
	}
}
