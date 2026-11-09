package infrastructure

import (
	"crypto/x509"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// TokenSlot describes one slot the PKCS#11 module exposes.
type TokenSlot struct {
	// Index is the slot number the module reports.
	Index int
	// Description is the human-readable name of the slot.
	Description string
	// TokenLabel is the label of the token in the slot, empty when the slot is
	// empty or the token is not logged in.
	TokenLabel string
	// TokenSerial is the serial number of the token, when it reports one.
	TokenSerial string
	// Manufacturer is the manufacturer string of the token.
	Manufacturer string
	// LoginState says whether the session is logged in.
	LoginState string
	// PINState is what the card says about its PIN before anyone types it:
	// attempts failed, last attempt, locked.
	PINState domain.PINState
	// PINPad reports a reader that takes the PIN on its own keypad.
	PINPad bool
	// PUKState is what the card says about its PUK (the PKCS#11 security
	// officer PIN), which unlocks a locked PIN.
	PUKState domain.PINState
	// Limits are the PIN lengths the card accepts.
	Limits domain.PINLimits
	// Certificates are the certificates the token holds, one per key object
	// that has a certificate attached.
	Certificates []TokenCertificate
}

// TokenCertificate describes one certificate held by a token.
type TokenCertificate struct {
	// Subject is the distinguished name of the subject.
	Subject string
	// Issuer is the distinguished name of the issuer.
	Issuer string
	// Serial is the serial number in hexadecimal.
	Serial string
	// NotBefore and NotAfter are the validity window.
	NotBefore time.Time
	NotAfter  time.Time
	// SelfSigned reports whether the certificate signs itself.
	SelfSigned bool
	// KeyUsages lists the key usage bits the certificate declares.
	KeyUsages []string
	// Fingerprint is the SHA-256 digest in hexadecimal; with the serial, it is
	// what names the certificate to sign with.
	Fingerprint string
	// SignsByDefault marks the certificate a signature uses when none is named
	// (domain.CertificateChoice).
	SignsByDefault bool
	// Credential names a remote service's credential the certificate
	// belongs to; empty on a card.
	Credential string

	certificate *x509.Certificate
}

// TokenInspector enumerates what a PKCS#11 module exposes.
//
// It exists for the person holding a physical card who cannot make the tool
// work and does not know why. The alternative is asking them to run
// "pkcs11-tool -L" and paste the output into a support request, which tells
// them nothing about what this tool needs.
//
// The command reports what is there. It never reports a token as usable when it
// is not, and it never opens a session that requires a PIN, because a diagnostic
// that asks for a PIN and then fails is worse than one that says the card needs
// a PIN.
type TokenInspector struct {
	// Module is the path of the PKCS#11 shared library.
	Module string
	// Parameters are the initialisation parameters some modules need, such as
	// the NSS profile directory; empty for cards.
	Parameters string
	// PIN, when set, is used to log in. Leaving it empty opens the token
	// without a PIN, which is what a diagnostic should do first.
	PIN string
}

// Inspect lists the slots and the certificates of the module.
func (i TokenInspector) Inspect() ([]TokenSlot, error) {
	return inspectToken(i.Module, i.Parameters, i.PIN)
}

// describeCertificate renders the facts of a certificate that matter when
// choosing which key to sign with.
func describeCertificate(certificate *x509.Certificate) TokenCertificate {
	if certificate == nil {
		return TokenCertificate{}
	}
	return TokenCertificate{
		Subject:     certificate.Subject.String(),
		Issuer:      certificate.Issuer.String(),
		Serial:      certificate.SerialNumber.Text(16),
		NotBefore:   certificate.NotBefore,
		NotAfter:    certificate.NotAfter,
		SelfSigned:  certificate.Subject.String() == certificate.Issuer.String(),
		KeyUsages:   usageNames(certificate),
		Fingerprint: domain.Fingerprint(certificate),
		certificate: certificate,
	}
}

// Parsed returns the certificate itself, for checks beyond the description
// such as the issuer's standing on a trusted list.
func (c TokenCertificate) Parsed() *x509.Certificate { return c.certificate }

// markDefault flags the certificate the card would sign with when none is
// named, so the listing shows the choice before anything is signed.
func markDefault(certificates []TokenCertificate) {
	index, err := domain.ChooseCertificateBy("").Pick(parsedCertificates(certificates))
	if err != nil {
		return
	}
	certificates[index].SignsByDefault = true
}

// parsedCertificates returns the certificates behind the descriptions.
func parsedCertificates(certificates []TokenCertificate) []*x509.Certificate {
	parsed := make([]*x509.Certificate, len(certificates))
	for index, certificate := range certificates {
		parsed[index] = certificate.certificate
	}
	return parsed
}

// usageNames renders the key usage bits as short names.
//
// A card can declare several, and the certificate profile decides which one
// matters: a document-signing certificate and a key-encipherment certificate
// are not interchangeable, and the difference decides whether the card can sign
// a document at all.
func usageNames(certificate *x509.Certificate) []string {
	if certificate == nil {
		return nil
	}

	bits := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "certSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
	}

	var names []string
	for _, entry := range bits {
		if certificate.KeyUsage&entry.bit != 0 {
			names = append(names, entry.name)
		}
	}
	return names
}
