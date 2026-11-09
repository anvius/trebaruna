package domain_test

import (
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

func cardIntent(card domain.CardCertificate, pin string) domain.SigningIntent {
	intent := validIntent()
	intent.Key = domain.CertificateFile{}
	intent.Card = card.Key(pin)
	return intent
}

func signatureCard(state signing.PINState) domain.CardCertificate {
	return domain.CardCertificate{Token: "DNI electrónico", Fingerprint: "a18a8855", PIN: state}
}

// TestACardReplacesTheCertificateFile: with a card chosen, no file is needed.
func TestACardReplacesTheCertificateFile(t *testing.T) {
	if err := cardIntent(signatureCard(signing.PINReady), "1234").Validate(); err != nil {
		t.Fatalf("a card with its PIN must be enough: %v", err)
	}
}

// TestACardIsRefusedBeforeAnAttemptIsSpent: what the card already says stops
// the signature in the window, before the command runs.
func TestACardIsRefusedBeforeAnAttemptIsSpent(t *testing.T) {
	cases := []struct {
		state signing.PINState
		pin   string
		want  domain.ProblemCode
	}{
		{signing.PINReady, "", domain.ProblemMissingPIN},
		{signing.PINLocked, "1234", domain.ProblemCardLocked},
		{signing.PINToBeChanged, "1234", domain.ProblemPINExpired},
		{signing.PINNotSet, "1234", domain.ProblemPINExpired},
	}
	for _, entry := range cases {
		err := cardIntent(signatureCard(entry.state), entry.pin).Validate()
		var problem domain.Problem
		if !errors.As(err, &problem) || problem.Code != entry.want {
			t.Errorf("%s with PIN %q: %v, want %s", entry.state, entry.pin, err, entry.want)
		}
		if !problem.StopsCard() {
			t.Errorf("%s must stop a batch", entry.want)
		}
	}
}

// TestAKeypadOrALoginlessCardNeedsNoTypedPIN.
func TestAKeypadOrALoginlessCardNeedsNoTypedPIN(t *testing.T) {
	keypad := signatureCard(signing.PINReady)
	keypad.PINPad = true
	if err := cardIntent(keypad, "").Validate(); err != nil {
		t.Errorf("a keypad reader takes the PIN itself: %v", err)
	}
	if err := cardIntent(signatureCard(signing.PINNotRequired), "").Validate(); err != nil {
		t.Errorf("a card without login needs no PIN: %v", err)
	}
	if err := cardIntent(signatureCard(signing.PINFinalTry), "1234").Validate(); err != nil {
		t.Errorf("a card on its last attempt can still sign: %v", err)
	}
}

// TestOnlyCardProblemsStopABatch: a missing authority does not make the next
// document's PIN attempt any riskier.
func TestOnlyCardProblemsStopABatch(t *testing.T) {
	if (domain.Problem{Code: domain.ProblemMissingTSA}).StopsCard() {
		t.Error("a missing authority must not stop the card")
	}
	if !(domain.Problem{Code: domain.ProblemWrongPIN}).StopsCard() {
		t.Error("a wrong PIN must stop the card")
	}
}
