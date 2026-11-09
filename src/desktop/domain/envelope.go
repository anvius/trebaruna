package domain

import "strings"

// EncryptionIntent is a document to encrypt for the people whose
// certificates are given: the .p7e it becomes opens only with their keys.
type EncryptionIntent struct {
	DocumentPath string
	// Recipients are certificate files (.pem, .cer, .crt, .der).
	Recipients []string
}

// Validate reports what is missing before any process is spawned.
func (i EncryptionIntent) Validate() error {
	if strings.TrimSpace(i.DocumentPath) == "" {
		return Problem{Code: ProblemMissingDocument}
	}
	if len(i.Recipients) == 0 {
		return Problem{Code: ProblemMissingRecipient}
	}
	return nil
}

// SealedEnvelope is the .p7e written, and the names of the people who can
// open it.
type SealedEnvelope struct {
	Path       string
	Recipients []string
}

// OpeningIntent is an envelope to open with the person's own key: a
// certificate file or a card, as chosen to sign.
type OpeningIntent struct {
	EnvelopePath string
	Key          CertificateFile
	Card         CardKey
}

// Validate reports what is missing before any process is spawned.
func (i OpeningIntent) Validate() error {
	if strings.TrimSpace(i.EnvelopePath) == "" {
		return Problem{Code: ProblemMissingDocument}
	}
	return keyProblem(i.Key, i.Card)
}

// OpenedEnvelope is the document taken out of an envelope.
type OpenedEnvelope struct {
	Path string
	Size int64
}

// IsEnvelope recognises an encrypted envelope by its suffix.
func IsEnvelope(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".p7e")
}
