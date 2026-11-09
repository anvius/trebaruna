// Package infrastructure adapts encrypted envelopes to CMS and to the keys
// the signing slice loads.
package infrastructure

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/encryption/application"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
	signinginfra "codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
)

// CMSSealer writes CMS EnvelopedData with AES-256-CBC.
type CMSSealer struct{}

// Seal encrypts the content for the recipients.
func (CMSSealer) Seal(content []byte, recipients []*x509.Certificate, oaep bool) ([]byte, error) {
	transport := cms.PKCS1v15
	if oaep {
		transport = cms.OAEP
	}
	return cms.Seal(content, recipients, transport)
}

// KeyOpener opens envelopes with the key of a file, a card or a store.
type KeyOpener struct{}

// Open finds the certificate the envelope names — on a card, by reading its
// certificates without the PIN — loads that key and decrypts.
func (KeyOpener) Open(envelope []byte, key signing.Signer) ([]byte, error) {
	recipients, err := cms.Recipients(envelope)
	if err != nil {
		return nil, err
	}
	if key.KeySource() == signing.FromToken && key.CertificateChoice().Automatic() {
		if chosen, found := recipientOnCard(key, recipients); found {
			key = key.Choosing(chosen)
		}
	}

	pair, err := signinginfra.LoadKeyPair(key)
	if err != nil {
		return nil, err
	}
	defer pair.Close()
	decrypter, ok := pair.Signer.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("the key of %s cannot decrypt", pair.Name)
	}
	content, err := cms.Open(envelope, pair.Certificate, decrypter)
	if errors.Is(err, cms.ErrNotARecipient) {
		return nil, fmt.Errorf("%w (%s); it was encrypted for: %s", err, pair.Name, describe(recipients))
	}
	return content, err
}

// recipientOnCard picks, among the certificates a card shows without a PIN,
// the one the envelope was encrypted for.
func recipientOnCard(key signing.Signer, recipients []cms.RecipientID) (signing.CertificateChoice, bool) {
	slots, err := signinginfra.TokenInspector{Module: key.PKCS11Module(), Parameters: key.PKCS11Parameters()}.Inspect()
	if err != nil {
		return signing.CertificateChoice{}, false
	}
	for _, slot := range slots {
		if key.PKCS11Token() != "" && slot.TokenLabel != key.PKCS11Token() {
			continue
		}
		for _, certificate := range slot.Certificates {
			parsed := certificate.Parsed()
			for _, recipient := range recipients {
				if parsed != nil && recipient.Matches(parsed) {
					return signing.ChooseCertificateBy(certificate.Fingerprint), true
				}
			}
		}
	}
	return signing.CertificateChoice{}, false
}

// describe names the recipients by serial, which is all an envelope says.
func describe(recipients []cms.RecipientID) string {
	names := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		names = append(names, "serial "+recipient.Serial.Text(16))
	}
	return strings.Join(names, ", ")
}

// LocalFiles reads and writes the file system.
type LocalFiles struct{}

// Read reads a file.
func (LocalFiles) Read(path string) ([]byte, error) { return os.ReadFile(path) }

// Exists reports whether a path exists.
func (LocalFiles) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Write writes a file readable only by its owner: an envelope's content is
// confidential by definition.
func (LocalFiles) Write(path string, content []byte) error { return os.WriteFile(path, content, 0o600) }

// compile-time checks.
var (
	_ application.Sealer = CMSSealer{}
	_ application.Opener = KeyOpener{}
	_ application.Files  = LocalFiles{}
)
