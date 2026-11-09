package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
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
		module = flags.String("module", "", "path of the PKCS#11 module (default: OpenSC, found on this system)")
		pin    = flags.String("pin", "", "PIN of the token, optional for listing (or $TREBARUNA_PIN)")
		asJSON = flags.Bool("json", false, "machine-readable output")
	)

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	path, err := moduleOrOpenSC(*module)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}

	inspector := infrastructure.TokenInspector{
		Module: path,
		PIN:    secretFrom(*pin, pinVariable),
	}

	slots, err := inspector.Inspect()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}

	if *asJSON {
		return printTokenJSON(stdout, slots)
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

// printTokenJSON writes the slots as JSON.
func printTokenJSON(stdout io.Writer, slots []infrastructure.TokenSlot) int {
	fmt.Fprintln(stdout, "{")
	fmt.Fprintln(stdout, `  "slots": [`)
	for index, slot := range slots {
		fmt.Fprintln(stdout, "    {")
		fmt.Fprintf(stdout, "      \"index\": %d,\n", slot.Index)
		fmt.Fprintf(stdout, "      \"description\": %s,\n", quoteJSON(slot.Description))
		fmt.Fprintf(stdout, "      \"token\": %s,\n", quoteJSON(slot.TokenLabel))
		fmt.Fprintf(stdout, "      \"manufacturer\": %s,\n", quoteJSON(slot.Manufacturer))
		fmt.Fprintf(stdout, "      \"serial\": %s,\n", quoteJSON(slot.TokenSerial))
		fmt.Fprintf(stdout, "      \"login\": %s,\n", quoteJSON(slot.LoginState))
		fmt.Fprintln(stdout, `      "certificates": [`)
		for position, certificate := range slot.Certificates {
			separator := ","
			if position == len(slot.Certificates)-1 {
				separator = ""
			}
			fmt.Fprintf(stdout, "        {\"subject\": %s, \"issuer\": %s, \"serial\": %s, \"fingerprint\": %s, "+
				"\"signs_by_default\": %t, "+
				"\"not_before\": %s, \"not_after\": %s, \"self_signed\": %t, \"key_usage\": %s}%s\n",
				quoteJSON(certificate.Subject),
				quoteJSON(certificate.Issuer),
				quoteJSON(certificate.Serial),
				quoteJSON(certificate.Fingerprint),
				certificate.SignsByDefault,
				quoteJSON(certificate.NotBefore.UTC().Format("2006-01-02T15:04:05Z07:00")),
				quoteJSON(certificate.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00")),
				certificate.SelfSigned,
				quoteJSON(strings.Join(certificate.KeyUsages, ",")),
				separator)
		}
		fmt.Fprintln(stdout, "      ]")
		separator := ","
		if index == len(slots)-1 {
			separator = ""
		}
		fmt.Fprintf(stdout, "    }%s\n", separator)
	}
	fmt.Fprintln(stdout, "  ]")
	fmt.Fprintln(stdout, "}")
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

// quoteJSON renders a string as a JSON literal.
func quoteJSON(value string) string {
	replaced := strings.ReplaceAll(value, `\`, `\\`)
	replaced = strings.ReplaceAll(replaced, `"`, `\"`)
	return `"` + replaced + `"`
}
