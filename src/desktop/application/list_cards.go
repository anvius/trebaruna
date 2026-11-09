package application

import (
	"context"
	"sort"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// CardReader lists the certificates of the cards in the readers, without a
// PIN: listing must never spend an attempt.
type CardReader interface {
	Cards(ctx context.Context) ([]domain.CardCertificate, error)
}

// ListCards is the use case behind the card source of the signing form: what
// cards are in the readers, whose certificates they hold, and whether each card
// can sign now or is locked.
type ListCards struct {
	reader CardReader
}

// NewListCards wires the use case.
func NewListCards(reader CardReader) *ListCards {
	return &ListCards{reader: reader}
}

// Execute lists the certificates, the one each card signs with by default
// first, so the form can offer it without asking.
func (u *ListCards) Execute(ctx context.Context) ([]domain.CardCertificate, error) {
	certificates, err := u.reader.Cards(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(certificates, func(a, b int) bool {
		return certificates[a].SignsByDefault && !certificates[b].SignsByDefault
	})
	return certificates, nil
}
