package cli

// `pignus certificate` — inspect a certificate on its own.
//
// Asking about a certificate is useful on its own: you can ask about a certificate
// without a document. That matters in daily use: "does my card expire before the
// contract does?", "is this the right certificate?", "why does my signature fail
// on the other machine?". Without it the user must sign a throwaway file to find
// out, which is a needless round trip.

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"codeberg.org/anvius/pignus/src/signing/domain"
	"codeberg.org/anvius/pignus/src/signing/domain/identity"
	"codeberg.org/anvius/pignus/src/signing/infrastructure"
	trustdomain "codeberg.org/anvius/pignus/src/trust/domain"
	verificationinfra "codeberg.org/anvius/pignus/src/verification/infrastructure"
)

// runCertificate implements `pignus certificate <file>`.
func runCertificate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("certificate", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		passphrase = flags.String("pass", "", "passphrase for a P12 or PEM bundle")
		territory  = flags.String("territory", defaultTerritory(), "trust list for the issuer verdict")
		asJSON     = flags.Bool("json", false, "machine-readable output")
	)

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: pignus certificate <file.p12|file.pem|file.crt> [flags]")
		flags.PrintDefaults()
	}

	path, remaining, err := extractDocument(args)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		flags.Usage()
		return exitUsage
	}
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}

	certificates, err := loadCertificates(path, *passphrase)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	if len(certificates) == 0 {
		fmt.Fprintf(stderr, "%q contains no certificate\n", path)
		return exitInvalid
	}

	list, _ := verificationinfra.NewCachedTrustProvider().Load(*territory)
	roots, _, _ := list.AnchorPool()

	now := time.Now()
	if *asJSON {
		var entries []map[string]any
		for _, certificate := range certificates {
			entries = append(entries, describeCertificateForJSON(certificate, roots, list, now))
		}
		encodeJSONValue(stdout, map[string]any{"path": path, "certificates": entries})
		return exitOK
	}

	for _, certificate := range certificates {
		printCertificate(stdout, certificate, roots, list, now)
	}
	return exitOK
}

// describeCertificateForJSON builds the machine-readable form.
func describeCertificateForJSON(
	certificate *x509.Certificate,
	roots *x509.CertPool,
	list trustdomain.TrustList,
	now time.Time,
) map[string]any {
	verdict := trustdomain.EvaluateIssuer(certificate, roots, list)
	remaining := certificate.NotAfter.Sub(now)

	return map[string]any{
		"subject":      certificate.Subject.String(),
		"name":         identity.FromCertificate(certificate).Name,
		"identifier":   identity.FromCertificate(certificate).Identifier,
		"issuer":       certificate.Issuer.String(),
		"serial":       certificate.SerialNumber.String(),
		"not_before":   certificate.NotBefore.UTC().Format(time.RFC3339),
		"not_after":    certificate.NotAfter.UTC().Format(time.RFC3339),
		"expired":      now.After(certificate.NotAfter),
		"days_left":    int(remaining.Hours() / 24),
		"self_signed":  certificate.Issuer.String() == certificate.Subject.String(),
		"provider":     string(verdict.Provider),
		"trusted":      verdict.Trusted,
		"qualified":    verdict.Qualified,
		"verdict_note": verdict.Reason,
	}
}

// printCertificate writes the human-readable form.
func printCertificate(
	writer io.Writer,
	certificate *x509.Certificate,
	roots *x509.CertPool,
	list trustdomain.TrustList,
	now time.Time,
) {
	verdict := trustdomain.EvaluateIssuer(certificate, roots, list)
	remaining := certificate.NotAfter.Sub(now)

	fmt.Fprintf(writer, "%s\n", identity.FromCertificate(certificate).Name)
	if identifier := identity.FromCertificate(certificate).Identifier; identifier != "" {
		fmt.Fprintf(writer, "  identificador  %s\n", identifier)
	}
	fmt.Fprintf(writer, "  emisor         %s\n", firstOf(append(certificate.Issuer.Organization, certificate.Issuer.CommonName)...))
	fmt.Fprintf(writer, "  validez        %s → %s\n",
		certificate.NotBefore.Format("2006-01-02"), certificate.NotAfter.Format("2006-01-02"))

	switch {
	case now.After(certificate.NotAfter):
		fmt.Fprintf(writer, "  estado         CADUCADO hace %d días\n", int(-remaining.Hours()/24))
	case remaining.Hours() < 24*30:
		fmt.Fprintf(writer, "  estado         caduca en %d días\n", int(remaining.Hours()/24))
	default:
		fmt.Fprintf(writer, "  estado         válido, %d días restantes\n", int(remaining.Hours()/24))
	}

	fmt.Fprintf(writer, "  confianza      %s — %s\n", verdict.Provider, verdict.Reason)
}

// loadCertificates reads certificates from a P12, a PEM bundle or a bare DER file.
func loadCertificates(path, passphrase string) ([]*x509.Certificate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	// A P12 is DER and starts with 0x30; a PEM starts with "-----BEGIN".
	if block, rest := pem.Decode(content); block != nil {
		certificates, err := certificatesFromPEM(content)
		if err != nil {
			return nil, err
		}
		_ = block
		_ = rest
		return certificates, nil
	}

	// Try PKCS#12 first, since that is what a card export usually is.
	keyPair, p12Err := infrastructure.LoadKeyPair(mustSigner(path, content, passphrase))
	if p12Err == nil && keyPair.Certificate != nil {
		return append([]*x509.Certificate{keyPair.Certificate}, keyPair.Chain...), nil
	}

	// A bare DER certificate.
	if certificate, err := x509.ParseCertificate(content); err == nil {
		return []*x509.Certificate{certificate}, nil
	}

	return nil, fmt.Errorf("%q is not a certificate, a PEM bundle or a PKCS#12 file", path)
}

// certificatesFromPEM reads every CERTIFICATE block.
func certificatesFromPEM(content []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	remaining := content
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest

		if !strings.Contains(block.Type, "CERTIFICATE") {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certificates = append(certificates, certificate)
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("the PEM file contains no certificate")
	}
	return certificates, nil
}

// mustSigner builds a domain signer so LoadKeyPair can decode a P12.
func mustSigner(path string, content []byte, passphrase string) domain.Signer {
	signer, err := domain.NewSigner(path, domain.FromP12,
		domain.WithKeyMaterial(content), domain.WithPassphrase(passphrase))
	if err != nil {
		// Fall back to the PEM source; LoadKeyPair reports the real error.
		signer, _ = domain.NewSigner(path, domain.FromPEM, domain.WithKeyMaterial(content))
	}
	return signer
}

// firstOf returns the first non-empty value.
func firstOf(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "—"
}
