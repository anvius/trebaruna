package application

import (
	"context"
	"fmt"

	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// Opener decrypts an envelope with the key a signer describes (a file, a
// card or a store), which never leaves its place: it only decrypts the
// envelope's content key.
type Opener interface {
	Open(envelope []byte, key signing.Signer) ([]byte, error)
}

// DecryptDocument takes the document out of an envelope encrypted for the
// person's certificate.
type DecryptDocument struct {
	files  Files
	opener Opener
}

// NewDecryptDocument wires the use case.
func NewDecryptDocument(files Files, opener Opener) *DecryptDocument {
	return &DecryptDocument{files: files, opener: opener}
}

// DecryptRequest names the envelope, the key and, optionally, the output.
type DecryptRequest struct {
	Envelope string
	Key      signing.Signer
	Output   string
}

// Execute decrypts and writes the document, never over an existing file.
func (u *DecryptDocument) Execute(_ context.Context, request DecryptRequest) (encryption.Decrypted, error) {
	output := request.Output
	if output == "" {
		output = encryption.DecryptedName(request.Envelope)
	}
	if u.files.Exists(output) {
		return encryption.Decrypted{}, fmt.Errorf("%w: %s (choose another with --out)", ErrWouldOverwrite, output)
	}
	envelope, err := u.files.Read(request.Envelope)
	if err != nil {
		return encryption.Decrypted{}, err
	}
	content, err := u.opener.Open(envelope, request.Key)
	if err != nil {
		return encryption.Decrypted{}, err
	}
	if err := u.files.Write(output, content); err != nil {
		return encryption.Decrypted{}, err
	}
	return encryption.Decrypted{Path: output, Size: len(content)}, nil
}
