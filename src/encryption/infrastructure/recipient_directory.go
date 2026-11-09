package infrastructure

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/encryption/application"
	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
)

// RecipientDirectory is the address book on disk: one PEM file per
// certificate, named by its SHA-256, in a directory only the user reads.
// Certificates are public, but whom a person writes to is not.
type RecipientDirectory struct {
	Directory string
}

// DefaultRecipientDirectory is $XDG_CONFIG_HOME/trebaruna/recipients.
func DefaultRecipientDirectory() (RecipientDirectory, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return RecipientDirectory{}, err
	}
	return RecipientDirectory{Directory: filepath.Join(base, "trebaruna", "recipients")}, nil
}

// Saved lists the certificates kept, by holder; a file that holds no
// certificate is skipped.
func (d RecipientDirectory) Saved() ([]encryption.SavedRecipient, error) {
	entries, err := os.ReadDir(d.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var saved []encryption.SavedRecipient
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		location := filepath.Join(d.Directory, entry.Name())
		certificate, err := readCertificate(location)
		if err != nil {
			continue
		}
		saved = append(saved, encryption.SavedFrom(certificate, location))
	}
	sort.Slice(saved, func(i, j int) bool { return strings.ToLower(saved[i].Holder) < strings.ToLower(saved[j].Holder) })
	return saved, nil
}

// Keep writes the certificate under its fingerprint; keeping it again
// changes nothing.
func (d RecipientDirectory) Keep(certificate *x509.Certificate) (encryption.SavedRecipient, error) {
	if err := os.MkdirAll(d.Directory, 0o700); err != nil {
		return encryption.SavedRecipient{}, err
	}
	location := filepath.Join(d.Directory, encryption.Fingerprint(certificate)+".pem")
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(location, content, 0o600); err != nil {
		return encryption.SavedRecipient{}, err
	}
	return encryption.SavedFrom(certificate, location), nil
}

// Forget removes the certificate with this fingerprint.
func (d RecipientDirectory) Forget(fingerprint string) error {
	if strings.ContainsAny(fingerprint, `/\.`) || fingerprint == "" {
		return fmt.Errorf("%w %q", encryption.ErrNoSavedRecipient, fingerprint)
	}
	err := os.Remove(filepath.Join(d.Directory, fingerprint+".pem"))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w %q", encryption.ErrNoSavedRecipient, fingerprint)
	}
	return err
}

// readCertificate reads a PEM or DER certificate.
func readCertificate(path string) (*x509.Certificate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(content); block != nil {
		content = block.Bytes
	}
	return x509.ParseCertificate(content)
}

// compile-time check.
var _ application.RecipientBook = RecipientDirectory{}
