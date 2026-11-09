package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// Encrypter writes the envelope of a document for its recipients.
type Encrypter interface {
	Encrypt(ctx context.Context, intent domain.EncryptionIntent) (domain.SealedEnvelope, error)
}

// EncryptForRecipients is the use case behind the envelopes window's first
// half: a document only the chosen people can open.
type EncryptForRecipients struct {
	encrypter Encrypter
}

// NewEncryptForRecipients wires the use case.
func NewEncryptForRecipients(encrypter Encrypter) *EncryptForRecipients {
	return &EncryptForRecipients{encrypter: encrypter}
}

// Execute refuses an incomplete intent before anything is spawned.
func (u *EncryptForRecipients) Execute(ctx context.Context, intent domain.EncryptionIntent) (domain.SealedEnvelope, error) {
	if err := intent.Validate(); err != nil {
		return domain.SealedEnvelope{}, err
	}
	return u.encrypter.Encrypt(ctx, intent)
}
