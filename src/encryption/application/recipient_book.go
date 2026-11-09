package application

import (
	"context"
	"crypto/x509"
	"time"

	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
)

// RecipientBook keeps recipients' certificates between sessions.
type RecipientBook interface {
	Saved() ([]encryption.SavedRecipient, error)
	Keep(certificate *x509.Certificate) (encryption.SavedRecipient, error)
	Forget(fingerprint string) error
}

// ListSavedRecipients lists the address book.
type ListSavedRecipients struct{ book RecipientBook }

// NewListSavedRecipients wires the use case.
func NewListSavedRecipients(book RecipientBook) *ListSavedRecipients {
	return &ListSavedRecipients{book: book}
}

// Execute lists the saved recipients.
func (u *ListSavedRecipients) Execute(context.Context) ([]encryption.SavedRecipient, error) {
	return u.book.Saved()
}

// KeepRecipient saves a recipient's certificate in the address book; a
// certificate that cannot receive envelopes now is not kept.
type KeepRecipient struct {
	book RecipientBook
	now  func() time.Time
}

// NewKeepRecipient wires the use case.
func NewKeepRecipient(book RecipientBook, now func() time.Time) *KeepRecipient {
	return &KeepRecipient{book: book, now: now}
}

// Execute keeps the certificate.
func (u *KeepRecipient) Execute(_ context.Context, certificate *x509.Certificate) (encryption.SavedRecipient, error) {
	if err := encryption.CanReceive(certificate, u.now()); err != nil {
		return encryption.SavedRecipient{}, err
	}
	return u.book.Keep(certificate)
}

// ForgetRecipient removes the one saved recipient a person names.
type ForgetRecipient struct{ book RecipientBook }

// NewForgetRecipient wires the use case.
func NewForgetRecipient(book RecipientBook) *ForgetRecipient { return &ForgetRecipient{book: book} }

// Execute forgets the recipient named by fingerprint or holder.
func (u *ForgetRecipient) Execute(_ context.Context, wanted string) (encryption.SavedRecipient, error) {
	saved, err := u.book.Saved()
	if err != nil {
		return encryption.SavedRecipient{}, err
	}
	recipient, err := encryption.Pick(saved, wanted)
	if err != nil {
		return encryption.SavedRecipient{}, err
	}
	return recipient, u.book.Forget(recipient.Fingerprint)
}
