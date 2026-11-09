package domain

import "strings"

// Signer identifies who signs, and how the private key is reached.
//
// The key source is a first-class business concept: "firmo con la tarjeta"
// and "firmo con un P12" produce the same signature but different trust
// expectations, and the user has the right to see which one happened.
type Signer struct {
	name         string
	keySource    KeySource
	keyMaterial  []byte
	passphrase   string
	pkcs11Module string
	pkcs11Token  string
	pkcs11PIN    string
	choice       CertificateChoice
}

// KeySource says where the private key lives.
type KeySource string

const (
	// FromP12 is a PKCS#12 file exported from any authority, or self-signed.
	FromP12 KeySource = "p12"

	// FromPEM is a PEM certificate plus an unencrypted or passphrase key.
	FromPEM KeySource = "pem"

	// FromToken is a smartcard reached through PKCS#11.
	FromToken KeySource = "token"
)

// NewSigner describes a signer without loading anything.
//
// Every field is validated here so the infrastructure layer never receives
// a half-built configuration.
// NameFromCertificate is the name of a signer nobody named. Once the
// certificate is loaded it is replaced by the holder printed on it, which is
// what a PDF reader shows next to the signature and what the receipt reports.
const NameFromCertificate = "certificate holder"

// NameFor returns the name the signature should carry: the one chosen for the
// signer, or the certificate holder when none was chosen.
func (s Signer) NameFor(holder string) string {
	if s.name == NameFromCertificate && strings.TrimSpace(holder) != "" {
		return holder
	}
	return s.name
}

func NewSigner(name string, source KeySource, options ...SignerOption) (Signer, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return Signer{}, ErrSignerWithoutName
	}

	s := Signer{name: trimmedName, keySource: source}
	for _, apply := range options {
		apply(&s)
	}

	switch s.keySource {
	case FromP12:
		if len(s.keyMaterial) == 0 {
			return Signer{}, ErrP12WithoutContent
		}
	case FromPEM:
		if len(s.keyMaterial) == 0 {
			return Signer{}, ErrPEMWithoutContent
		}
	case FromToken:
		if strings.TrimSpace(s.pkcs11Module) == "" {
			return Signer{}, ErrTokenWithoutModule
		}
	case "":
		return Signer{}, ErrSignerWithoutSource
	default:
		return Signer{}, ErrSignerWithoutSource
	}

	return s, nil
}

// SignerOption customises a Signer during construction.
type SignerOption func(*Signer)

// WithKeyMaterial attaches the raw bytes of a P12 or PEM bundle.
func WithKeyMaterial(data []byte) SignerOption {
	return func(s *Signer) { s.keyMaterial = data }
}

// WithPassphrase sets the P12 or PEM passphrase.
func WithPassphrase(passphrase string) SignerOption {
	return func(s *Signer) { s.passphrase = passphrase }
}

// WithToken points at a PKCS#11 module and the token to use.
func WithToken(module, tokenLabel, pin string) SignerOption {
	return func(s *Signer) {
		s.pkcs11Module = module
		s.pkcs11Token = tokenLabel
		s.pkcs11PIN = pin
	}
}

// WithCertificateChoice says which certificate of the card signs. Without it
// the card decides, and only when it leaves no doubt (CertificateChoice).
func WithCertificateChoice(choice CertificateChoice) SignerOption {
	return func(s *Signer) { s.choice = choice }
}

// Name returns the human-readable signer name.
func (s Signer) Name() string { return s.name }

// KeySource returns where the private key lives.
func (s Signer) KeySource() KeySource { return s.keySource }

// KeyMaterial returns the raw P12 or PEM bytes.
func (s Signer) KeyMaterial() []byte { return s.keyMaterial }

// Passphrase returns the P12 or PEM passphrase.
func (s Signer) Passphrase() string { return s.passphrase }

// PKCS11Module returns the PKCS#11 library path.
func (s Signer) PKCS11Module() string { return s.pkcs11Module }

// PKCS11Token returns the token label to select.
func (s Signer) PKCS11Token() string { return s.pkcs11Token }

// PKCS11PIN returns the token PIN.
func (s Signer) PKCS11PIN() string { return s.pkcs11PIN }

// CertificateChoice returns how the certificate of the card is chosen.
func (s Signer) CertificateChoice() CertificateChoice { return s.choice }
