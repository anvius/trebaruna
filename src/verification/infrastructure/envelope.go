package infrastructure

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"

	"github.com/digitorus/pkcs7"

	"codeberg.org/simplicer/trebaruna/src/verification/application"
)

// ErrDetachedEnvelope means the signature carries no document to extract.
var ErrDetachedEnvelope = errors.New("this is a detached signature: the document travels beside it, not inside")

// CMSEnvelopes opens CAdES envelopes in DER, BER, PEM or bare Base64, the
// forms .p7m files actually arrive in.
type CMSEnvelopes struct{}

// Open returns the content of the envelope.
func (CMSEnvelopes) Open(envelope []byte) ([]byte, error) {
	parsed, err := pkcs7.Parse(CMSBytes(envelope))
	if err != nil {
		return nil, err
	}
	if len(parsed.Content) == 0 {
		return nil, ErrDetachedEnvelope
	}
	return parsed.Content, nil
}

// IsEnvelope reports whether data is itself a signed envelope.
func (CMSEnvelopes) IsEnvelope(data []byte) bool {
	parsed, err := pkcs7.Parse(CMSBytes(data))
	return err == nil && len(parsed.Signers) > 0 && len(parsed.Content) > 0
}

// CMSBytes returns the binary form of a CMS structure given as DER/BER, as a
// PEM block, or as bare Base64 text (common for .p7m files mailed by
// Italian offices). Anything else is returned unchanged.
func CMSBytes(raw []byte) []byte {
	if block, _ := pem.Decode(raw); block != nil {
		return block.Bytes
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] != 0x30 {
		cleaned := bytes.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, trimmed)
		if decoded, err := base64.StdEncoding.DecodeString(string(cleaned)); err == nil && len(decoded) > 0 && decoded[0] == 0x30 {
			return decoded
		}
	}
	return raw
}

// LocalFiles reads and writes plain files for the extraction.
type LocalFiles struct{}

// Read reads a file.
func (LocalFiles) Read(path string) ([]byte, error) { return os.ReadFile(path) }

// Exists reports whether something is already at path.
func (LocalFiles) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Write writes a new file, readable by its owner and group.
func (LocalFiles) Write(path string, content []byte) error {
	return os.WriteFile(path, content, 0o640)
}

// compile-time checks.
var (
	_ application.EnvelopeOpener = CMSEnvelopes{}
	_ application.DocumentFiles  = LocalFiles{}
)
