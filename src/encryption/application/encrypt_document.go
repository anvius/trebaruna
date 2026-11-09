// Package application holds the use cases of encrypted envelopes.
package application

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
)

// ErrWouldOverwrite means the output path already exists.
var ErrWouldOverwrite = errors.New("refusing to overwrite an existing file")

// Files reads documents and writes envelopes and their contents.
type Files interface {
	Read(path string) ([]byte, error)
	Exists(path string) bool
	Write(path string, content []byte) error
}

// Sealer encrypts content for recipient certificates.
type Sealer interface {
	Seal(content []byte, recipients []*x509.Certificate, oaep bool) ([]byte, error)
}

// EncryptDocument is AutoFirma's digital envelope, the .p7e of Italian practice:
// a document only the named certificates' holders can open.
type EncryptDocument struct {
	files  Files
	sealer Sealer
	now    func() time.Time
}

// NewEncryptDocument wires the use case.
func NewEncryptDocument(files Files, sealer Sealer, now func() time.Time) *EncryptDocument {
	return &EncryptDocument{files: files, sealer: sealer, now: now}
}

// EncryptRequest names the document, its recipients and, optionally, the
// key transport and the output.
type EncryptRequest struct {
	Document   string
	Recipients []*x509.Certificate
	// OAEP sends the content key with RSA-OAEP instead of PKCS#1 v1.5, which
	// every tool reads.
	OAEP   bool
	Output string
}

// Execute checks every recipient before encrypting, and never overwrites.
func (u *EncryptDocument) Execute(_ context.Context, request EncryptRequest) (encryption.Envelope, error) {
	if len(request.Recipients) == 0 {
		return encryption.Envelope{}, encryption.ErrNoRecipients
	}
	names := make([]string, 0, len(request.Recipients))
	for _, recipient := range request.Recipients {
		if err := encryption.CanReceive(recipient, u.now()); err != nil {
			return encryption.Envelope{}, err
		}
		names = append(names, recipient.Subject.CommonName)
	}

	output := request.Output
	if output == "" {
		output = encryption.EncryptedName(request.Document)
	}
	if u.files.Exists(output) {
		return encryption.Envelope{}, fmt.Errorf("%w: %s (choose another with --out)", ErrWouldOverwrite, output)
	}
	content, err := u.files.Read(request.Document)
	if err != nil {
		return encryption.Envelope{}, err
	}
	sealed, err := u.sealer.Seal(content, request.Recipients, request.OAEP)
	if err != nil {
		return encryption.Envelope{}, err
	}
	if err := u.files.Write(output, sealed); err != nil {
		return encryption.Envelope{}, err
	}
	return encryption.Envelope{Path: output, Size: len(sealed), Recipients: names}, nil
}
