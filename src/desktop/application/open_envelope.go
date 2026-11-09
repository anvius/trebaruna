package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// EnvelopeOpener takes a document out of an envelope with the person's key.
type EnvelopeOpener interface {
	Open(ctx context.Context, intent domain.OpeningIntent) (domain.OpenedEnvelope, error)
}

// OpenEnvelope is the use case behind the envelopes window's second half:
// the document a .p7e carries, opened with the key chosen to sign.
type OpenEnvelope struct {
	opener EnvelopeOpener
}

// NewOpenEnvelope wires the use case.
func NewOpenEnvelope(opener EnvelopeOpener) *OpenEnvelope {
	return &OpenEnvelope{opener: opener}
}

// Execute refuses an incomplete intent before anything is spawned.
func (u *OpenEnvelope) Execute(ctx context.Context, intent domain.OpeningIntent) (domain.OpenedEnvelope, error) {
	if err := intent.Validate(); err != nil {
		return domain.OpenedEnvelope{}, err
	}
	return u.opener.Open(ctx, intent)
}
