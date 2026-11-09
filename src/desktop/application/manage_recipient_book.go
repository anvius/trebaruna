package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// RecipientBook is the address book of recipients' certificates.
type RecipientBook interface {
	Saved(ctx context.Context) ([]domain.SavedRecipient, error)
	Keep(ctx context.Context, path string) error
	Forget(ctx context.Context, fingerprint string) error
}

// ManageRecipientBook keeps or forgets recipients and returns the book as
// it is afterwards.
type ManageRecipientBook struct {
	book RecipientBook
}

// NewManageRecipientBook wires the use case.
func NewManageRecipientBook(book RecipientBook) *ManageRecipientBook {
	return &ManageRecipientBook{book: book}
}

// Execute applies the change, then lists the book. A certificate the book
// refuses (one that cannot receive envelopes) stops the change.
func (u *ManageRecipientBook) Execute(ctx context.Context, change domain.RecipientBookChange) ([]domain.SavedRecipient, error) {
	for _, path := range change.Keep {
		if err := u.book.Keep(ctx, path); err != nil {
			return nil, err
		}
	}
	if change.Forget != "" {
		if err := u.book.Forget(ctx, change.Forget); err != nil {
			return nil, err
		}
	}
	return u.book.Saved(ctx)
}
