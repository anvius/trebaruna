package infrastructure

import (
	"crypto/x509"
	"fmt"
	"time"

	"codeberg.org/anvius/trebaruna/src/signing/domain"
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
	// PIN, when set, is used to log in. Leaving it empty opens the token
	// without a PIN, which is what a diagnostic should do first.
	PIN string
}

// Inspect lists the slots and the certificates of the module.
func (i TokenInspector) Inspect() ([]TokenSlot, error) {
	return inspectToken(i.Module, i.PIN)
}

// describeCertificate renders the facts of a certificate that matter when
// choosing which key to sign with.
func describeCertificate(certificate *x509.Certificate) TokenCertificate {
	if certificate == nil {
		return TokenCertificate{}
	}
	return TokenCertificate{
		Subject:    certificate.Subject.String(),
		Issuer:     certificate.Issuer.String(),
		Serial:     certificate.SerialNumber.Text(16),
		NotBefore:  certificate.NotBefore,
		NotAfter:   certificate.NotAfter,
		SelfSigned: certificate.Subject.String() == certificate.Issuer.String(),
		KeyUsages:  usageNames(certificate),
	}
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

// tokenLabelOrDefault returns the label to look for, or a hint.
func tokenLabelOrDefault(label string) string {
	if label == "" {
		return "(no label given)"
	}
	return label
}

// formatSlot renders one slot for the terminal.
func formatSlot(slot TokenSlot) string {
	out := fmt.Sprintf("slot %d: %s\n", slot.Index, slot.Description)
	if slot.TokenLabel == "" {
		return out + "  (no token present)\n"
	}
	out += fmt.Sprintf("  token:      %s\n", slot.TokenLabel)
	if slot.Manufacturer != "" {
		out += fmt.Sprintf("  maker:      %s\n", slot.Manufacturer)
	}
	if slot.TokenSerial != "" {
		out += fmt.Sprintf("  serial:     %s\n", slot.TokenSerial)
	}
	out += fmt.Sprintf("  login:      %s\n", slot.LoginState)
	for _, certificate := range slot.Certificates {
		out += fmt.Sprintf("  certificate: %s\n", certificate.Subject)
		out += fmt.Sprintf("    issuer:    %s\n", certificate.Issuer)
		out += fmt.Sprintf("    serial:    %s\n", certificate.Serial)
		out += fmt.Sprintf("    valid:     %s .. %s\n",
			certificate.NotBefore.UTC().Format(time.RFC3339),
			certificate.NotAfter.UTC().Format(time.RFC3339))
		if certificate.SelfSigned {
			out += "    note:      self-signed, no third-party trust\n"
		}
		if len(certificate.KeyUsages) > 0 {
			out += fmt.Sprintf("    key usage: %s\n", joinNames(certificate.KeyUsages))
		}
	}
	return out
}

// joinNames renders a list with commas.
func joinNames(names []string) string {
	out := ""
	for index, name := range names {
		if index > 0 {
			out += ", "
		}
		out += name
	}
	return out
}

// compile-time check.
var _ = domain.BES
