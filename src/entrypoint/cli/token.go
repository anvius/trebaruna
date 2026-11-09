package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/domain/identity"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	trustdomain "codeberg.org/simplicer/trebaruna/src/trust/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// runToken implements `trebaruna token`.
//
// It exists for the person holding a physical card who cannot make the tool
// work and does not know why. Without it, the advice is to run a command from
// another package and paste the output into a support request, which answers
// none of the questions the user actually has: is the reader seen, is the card
// in it, what is the token called, and what certificates does it hold.
func runToken(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("token", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		module    = flags.String("module", "", "path of the PKCS#11 module (default: OpenSC, found on this system)")
		territory = flags.String("territory", defaultTerritory(), "trust list for the issuers' standing in --json")
		firefox   = flags.Bool("firefox", false, "list the Firefox store instead of the cards")
		nssDB     = flags.String("nss-db", "", "list this NSS store directory instead of the cards")
		pin       = flags.String("pin", "", "PIN of the token, optional for listing (or $TREBARUNA_PIN)")
		asJSON    = flags.Bool("json", false, "machine-readable output")
	)

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	path, parameters, err := cardModule(*module, storeOptions{firefox: *firefox, directory: *nssDB})
	if errors.Is(err, errNoFirefoxProfile) && *asJSON {
		// For a listing, no Firefox store holds no certificate: the window
		// says how to import one instead of showing an error.
		return printTokenJSON(stdout, nil, *territory)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}

	inspector := infrastructure.TokenInspector{
		Module:     path,
		Parameters: parameters,
		PIN:        secretFrom(*pin, pinVariable),
	}

	slots, err := inspector.Inspect()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}

	if *asJSON {
		return printTokenJSON(stdout, slots, *territory)
	}

	if len(slots) == 0 {
		fmt.Fprintln(stderr, "the module exposes no slots")
		fmt.Fprintln(stderr, "  check: the reader is connected and pcscd is running")
		return exitInvalid
	}

	for _, slot := range slots {
		fmt.Fprint(stdout, formatTokenSlot(slot))
	}

	return exitOK
}

// tokenSlotJSON is one slot of `token --json`.
type tokenSlotJSON struct {
	Index        int                    `json:"index"`
	Description  string                 `json:"description"`
	Token        string                 `json:"token"`
	Manufacturer string                 `json:"manufacturer"`
	Serial       string                 `json:"serial"`
	Login        string                 `json:"login"`
	PIN          string                 `json:"pin"`
	PINPad       bool                   `json:"pinpad"`
	Certificates []tokenCertificateJSON `json:"certificates"`
}

// tokenCertificateJSON is one certificate of a card, with the same identity
// and trust fields `certificate --json` prints for a file.
type tokenCertificateJSON struct {
	Subject        string `json:"subject"`
	Name           string `json:"name"`
	Identifier     string `json:"identifier"`
	Issuer         string `json:"issuer"`
	IssuerName     string `json:"issuer_name"`
	Locality       string `json:"locality"`
	Serial         string `json:"serial"`
	Fingerprint    string `json:"fingerprint"`
	SignsByDefault bool   `json:"signs_by_default"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SelfSigned     bool   `json:"self_signed"`
	KeyUsage       string `json:"key_usage"`
	Trusted        bool   `json:"trusted"`
	Qualified      bool   `json:"qualified"`
	Provider       string `json:"provider"`
}

// printTokenJSON writes the slots as JSON, judging each certificate's issuer
// against the trusted list of the territory.
func printTokenJSON(stdout io.Writer, slots []infrastructure.TokenSlot, territory string) int {
	list, _ := verificationinfra.NewCachedTrustProvider().Load(territory)
	roots, _, _ := list.AnchorPool()

	printed := struct {
		Slots []tokenSlotJSON `json:"slots"`
	}{Slots: []tokenSlotJSON{}}
	for _, slot := range slots {
		entry := tokenSlotJSON{
			Index: slot.Index, Description: slot.Description, Token: slot.TokenLabel,
			Manufacturer: slot.Manufacturer, Serial: slot.TokenSerial, Login: slot.LoginState,
			PIN: string(slot.PINState), PINPad: slot.PINPad, Certificates: []tokenCertificateJSON{},
		}
		for _, certificate := range slot.Certificates {
			described := tokenCertificateJSON{
				Subject: certificate.Subject, Issuer: certificate.Issuer, Serial: certificate.Serial,
				Fingerprint: certificate.Fingerprint, SignsByDefault: certificate.SignsByDefault,
				NotBefore:  certificate.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:   certificate.NotAfter.UTC().Format(time.RFC3339),
				SelfSigned: certificate.SelfSigned, KeyUsage: strings.Join(certificate.KeyUsages, ","),
			}
			if parsed := certificate.Parsed(); parsed != nil {
				holder := identity.FromCertificate(parsed)
				verdict := trustdomain.EvaluateIssuer(parsed, roots, list)
				described.Name, described.Identifier = holder.Name, holder.Identifier
				described.IssuerName = firstOf(append(parsed.Issuer.Organization, parsed.Issuer.CommonName)...)
				described.Locality = firstNonEmptyString(slices.Concat(parsed.Subject.Locality, parsed.Subject.Province)...)
				described.Trusted, described.Qualified = verdict.Trusted, verdict.Qualified
				described.Provider = string(verdict.Provider)
			}
			entry.Certificates = append(entry.Certificates, described)
		}
		printed.Slots = append(printed.Slots, entry)
	}
	encodeJSONValue(stdout, printed)
	return exitOK
}

// formatTokenSlot renders one slot for the terminal.
//
// The lines say what the user needs in order to act: the label goes in
// --token, the serial or the fingerprint in --certificate, and the key usage
// says whether the certificate can sign a document at all.
func formatTokenSlot(slot infrastructure.TokenSlot) string {
	out := fmt.Sprintf("slot %d: %s\n", slot.Index, slot.Description)
	if slot.TokenLabel == "" {
		return out + "  (no token in this slot)\n"
	}

	out += fmt.Sprintf("  token:      %s\n", slot.TokenLabel)
	if slot.Manufacturer != "" {
		out += fmt.Sprintf("  maker:      %s\n", slot.Manufacturer)
	}
	if slot.TokenSerial != "" {
		out += fmt.Sprintf("  serial:     %s\n", slot.TokenSerial)
	}
	out += fmt.Sprintf("  login:      %s\n", slot.LoginState)
	if note := pinNote(slot); note != "" {
		out += fmt.Sprintf("  pin:        %s\n", note)
	}

	if len(slot.Certificates) == 0 {
		out += "  (no certificates readable on this token)\n"
		return out
	}

	for _, certificate := range slot.Certificates {
		out += fmt.Sprintf("  certificate: %s\n", certificate.Subject)
		out += fmt.Sprintf("    issuer:    %s\n", certificate.Issuer)
		out += fmt.Sprintf("    serial:    %s\n", certificate.Serial)
		out += fmt.Sprintf("    sha-256:   %s\n", certificate.Fingerprint)
		if certificate.SignsByDefault {
			out += "    signs:     by default, when no --certificate is given\n"
		}
		out += fmt.Sprintf("    valid:     %s .. %s\n",
			certificate.NotBefore.UTC().Format("2006-01-02 15:04:05Z"),
			certificate.NotAfter.UTC().Format("2006-01-02 15:04:05Z"))
		if certificate.SelfSigned {
			out += "    note:      self-signed, so it carries no third-party trust\n"
		}
		if len(certificate.KeyUsages) > 0 {
			out += fmt.Sprintf("    key usage: %s\n", strings.Join(certificate.KeyUsages, ", "))
			if !signsDocuments(certificate) {
				out += "    note:      this certificate does not declare a signing usage\n"
			}
		} else {
			// A certificate that declares no key usage at all is unrestricted.
			// Saying it cannot sign would be wrong, and it is the case most
			// certificates produced by a quick command land in.
			out += "    key usage: not declared, so unrestricted\n"
		}
	}

	return out
}

// pinNote says what the PIN state means for the next attempt, or nothing in
// the ordinary case.
func pinNote(slot infrastructure.TokenSlot) string {
	notes := map[domain.PINState]string{
		domain.PINCountLow:    "a wrong PIN was entered: few attempts are left",
		domain.PINFinalTry:    "one more wrong PIN locks the card",
		domain.PINLocked:      "locked: unlock it with its PUK",
		domain.PINToBeChanged: "must be changed before the card signs",
		domain.PINNotSet:      "not set yet",
	}
	note := notes[slot.PINState]
	if slot.PINPad {
		note = strings.TrimPrefix(note+"; typed on the reader's keypad", "; ")
	}
	return note
}

// signsDocuments reports whether the certificate declares a usage that allows
// signing a document.
//
// A certificate with no key usage declared is unrestricted, so it is treated as
// able to sign. Only an explicit absence counts as a restriction.
func signsDocuments(certificate infrastructure.TokenCertificate) bool {
	if len(certificate.KeyUsages) == 0 {
		return true
	}
	for _, usage := range certificate.KeyUsages {
		if usage == "digitalSignature" || usage == "contentCommitment" || usage == "keyAgreement" {
			return true
		}
	}
	return false
}
