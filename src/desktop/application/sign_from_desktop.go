// Package application runs a signing intent without knowing about windows.
package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// Signer produces the signature an intent describes.
//
// The window never learns how: today the adapter drives the trebaruna command,
// so the desktop and the console share one implementation, but the use case
// would not change if it signed in process.
type Signer interface {
	Sign(ctx context.Context, intent domain.SigningIntent) (domain.Receipt, error)
}

// SignFromDesktop is the use case behind the Sign button.
//
// It validates, delegates to the signer, and confirms the signed file exists
// before telling the user it does. It never touches Fyne.
type SignFromDesktop struct {
	signer Signer
	exists func(path string) bool
}

// NewSignFromDesktop wires the use case.
func NewSignFromDesktop(signer Signer, exists func(string) bool) *SignFromDesktop {
	return &SignFromDesktop{signer: signer, exists: exists}
}

// Execute validates and signs.
func (u *SignFromDesktop) Execute(ctx context.Context, intent domain.SigningIntent) (domain.Receipt, error) {
	if err := intent.Validate(); err != nil {
		return domain.Receipt{}, err
	}

	receipt, err := u.signer.Sign(ctx, intent)
	if err != nil {
		return domain.Receipt{}, err
	}

	// A signer that reports success without leaving a file behind is the one
	// failure a user cannot diagnose alone, so it is named instead of trusted.
	if u.exists != nil && !u.exists(receipt.SignedPath) {
		return domain.Receipt{}, domain.Problem{Code: domain.ProblemNoOutput, Detail: receipt.SignedPath}
	}

	return receipt, nil
}
