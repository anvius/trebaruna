package application

import (
	"errors"
	"fmt"

	verification "codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// EnvelopeOpener returns the content of a CMS envelope, and whether that
// content is itself an envelope.
type EnvelopeOpener interface {
	Open(envelope []byte) (content []byte, err error)
	IsEnvelope(data []byte) bool
}

// DocumentFiles reads envelopes and writes what they contain.
type DocumentFiles interface {
	Read(path string) ([]byte, error)
	Exists(path string) bool
	Write(path string, content []byte) error
}

// ErrWouldOverwrite means the output path already exists.
var ErrWouldOverwrite = errors.New("refusing to overwrite an existing file")

// ExtractDocument takes the signed document out of its envelopes: what
// AutoFirma calls "extraer datos".
type ExtractDocument struct {
	files  DocumentFiles
	opener EnvelopeOpener
}

// NewExtractDocument wires the use case.
func NewExtractDocument(files DocumentFiles, opener EnvelopeOpener) *ExtractDocument {
	return &ExtractDocument{files: files, opener: opener}
}

// ExtractRequest names the envelope and, optionally, where to write.
type ExtractRequest struct {
	Envelope string
	Output   string
}

// Execute opens every envelope down to the document and writes it, never
// over an existing file.
func (u *ExtractDocument) Execute(request ExtractRequest) (verification.ExtractedDocument, error) {
	data, err := u.files.Read(request.Envelope)
	if err != nil {
		return verification.ExtractedDocument{}, err
	}

	layers := 0
	for layers == 0 || u.opener.IsEnvelope(data) {
		content, err := u.opener.Open(data)
		if err != nil {
			if layers == 0 {
				return verification.ExtractedDocument{}, err
			}
			break
		}
		data = content
		layers++
	}

	output := request.Output
	if output == "" {
		output = verification.ExtractedName(request.Envelope)
	}
	if u.files.Exists(output) {
		return verification.ExtractedDocument{}, fmt.Errorf("%w: %s (choose another with --out)", ErrWouldOverwrite, output)
	}
	if err := u.files.Write(output, data); err != nil {
		return verification.ExtractedDocument{}, err
	}
	return verification.ExtractedDocument{Path: output, Layers: layers, Size: len(data)}, nil
}
