package application

import (
	"context"
	"crypto/x509"
	"time"

	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
)

// CertificateDirectory finds people's certificates, such as an LDAP
// directory that publishes them.
type CertificateDirectory interface {
	Find(ctx context.Context, who string) ([]*x509.Certificate, error)
}

// FoundCertificate is a certificate the directory gave, and why it cannot
// receive an envelope, when it cannot.
type FoundCertificate struct {
	Certificate *x509.Certificate
	Problem     error
}

// FindRecipient looks a person up in a certificate directory, by e-mail
// address or name, and says of each certificate found whether an envelope
// can be made for it: an RSA key that may encipher keys, still valid.
type FindRecipient struct {
	directory CertificateDirectory
	now       func() time.Time
}

// NewFindRecipient wires the use case.
func NewFindRecipient(directory CertificateDirectory, now func() time.Time) *FindRecipient {
	return &FindRecipient{directory: directory, now: now}
}

// Execute looks who up.
func (u *FindRecipient) Execute(ctx context.Context, who string) ([]FoundCertificate, error) {
	certificates, err := u.directory.Find(ctx, who)
	if err != nil {
		return nil, err
	}
	found := make([]FoundCertificate, len(certificates))
	for index, certificate := range certificates {
		found[index] = FoundCertificate{Certificate: certificate, Problem: encryption.CanReceive(certificate, u.now())}
	}
	return found, nil
}
