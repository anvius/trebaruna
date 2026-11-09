package application_test

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

type scriptedBook struct {
	calls   []string
	refuse  string
	listing []domain.SavedRecipient
}

func (b *scriptedBook) Saved(context.Context) ([]domain.SavedRecipient, error) {
	b.calls = append(b.calls, "saved")
	return b.listing, nil
}

func (b *scriptedBook) Keep(_ context.Context, path string) error {
	b.calls = append(b.calls, "keep "+path)
	if path == b.refuse {
		return errors.New("cannot receive envelopes")
	}
	return nil
}

func (b *scriptedBook) Forget(_ context.Context, fingerprint string) error {
	b.calls = append(b.calls, "forget "+fingerprint)
	return nil
}

func TestTheBookIsChangedThenListed(t *testing.T) {
	book := &scriptedBook{listing: []domain.SavedRecipient{{Holder: "ANNA BIANCHI"}}}
	use := application.NewManageRecipientBook(book)
	saved, err := use.Execute(context.Background(), domain.RecipientBookChange{Keep: []string{"/a.pem", "/b.pem"}, Forget: "ff00"})
	if err != nil || len(saved) != 1 || len(book.calls) != 4 || book.calls[0] != "keep /a.pem" || book.calls[2] != "forget ff00" || book.calls[3] != "saved" {
		t.Errorf("calls %v, saved %v, %v", book.calls, saved, err)
	}

	refused := &scriptedBook{refuse: "/b.pem"}
	if _, err := application.NewManageRecipientBook(refused).Execute(context.Background(),
		domain.RecipientBookChange{Keep: []string{"/a.pem", "/b.pem", "/c.pem"}, Forget: "ff00"}); err == nil || len(refused.calls) != 2 {
		t.Errorf("a refused certificate stops the change: %v %v", refused.calls, err)
	}
}
