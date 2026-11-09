package application_test

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

type scriptedCards struct {
	cards []domain.CardCertificate
	err   error
}

func (s scriptedCards) Cards(context.Context) ([]domain.CardCertificate, error) {
	return s.cards, s.err
}

func TestTheSigningCertificateIsOfferedFirst(t *testing.T) {
	reader := scriptedCards{cards: []domain.CardCertificate{
		{Fingerprint: "auth"}, {Fingerprint: "other"}, {Fingerprint: "sign", SignsByDefault: true},
	}}
	cards, err := application.NewListCards(reader).Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if cards[0].Fingerprint != "sign" || cards[1].Fingerprint != "auth" || cards[2].Fingerprint != "other" {
		t.Errorf("order %v: the default first, the rest as listed", []string{cards[0].Fingerprint, cards[1].Fingerprint, cards[2].Fingerprint})
	}
}

func TestAReaderFailureReachesTheForm(t *testing.T) {
	failure := errors.New("OpenSC was not found on this system")
	if _, err := application.NewListCards(scriptedCards{err: failure}).Execute(context.Background()); !errors.Is(err, failure) {
		t.Errorf("got %v", err)
	}
}
