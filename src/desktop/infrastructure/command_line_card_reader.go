package infrastructure

// No build tag: plain os/exec, tested by `make test` with a stand-in command.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// CommandLineCardReader lists the cards by running `trebaruna token --json`,
// which reads them without a PIN and judges each issuer against the trusted
// lists, so the window shows the verdict the command prints.
type CommandLineCardReader struct {
	BinaryPath string
}

// Cards runs the command and flattens its slots into certificates.
func (r CommandLineCardReader) Cards(ctx context.Context) ([]domain.CardCertificate, error) {
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, r.BinaryPath, "token", "--json")
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, errors.New(meaningfulLine(stderr.String(), stdout.String(), err))
	}

	var printed struct {
		Slots []struct {
			Description  string `json:"description"`
			Token        string `json:"token"`
			PIN          string `json:"pin"`
			PINPad       bool   `json:"pinpad"`
			Certificates []struct {
				Name           string `json:"name"`
				Identifier     string `json:"identifier"`
				IssuerName     string `json:"issuer_name"`
				Locality       string `json:"locality"`
				Serial         string `json:"serial"`
				Fingerprint    string `json:"fingerprint"`
				SignsByDefault bool   `json:"signs_by_default"`
				NotAfter       string `json:"not_after"`
				SelfSigned     bool   `json:"self_signed"`
				Trusted        bool   `json:"trusted"`
				Qualified      bool   `json:"qualified"`
			} `json:"certificates"`
		} `json:"slots"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		return nil, fmt.Errorf("the token command printed an unreadable answer: %w", err)
	}

	var certificates []domain.CardCertificate
	for _, slot := range printed.Slots {
		for _, certificate := range slot.Certificates {
			notAfter, err := time.Parse(time.RFC3339, certificate.NotAfter)
			if err != nil {
				return nil, fmt.Errorf("unreadable expiry %q: %w", certificate.NotAfter, err)
			}
			certificates = append(certificates, domain.CardCertificate{
				Token:          slot.Token,
				Reader:         slot.Description,
				PIN:            signing.PINState(slot.PIN),
				PINPad:         slot.PINPad,
				Fingerprint:    certificate.Fingerprint,
				Serial:         certificate.Serial,
				SignsByDefault: certificate.SignsByDefault,
				Summary: domain.CertificateSummary{
					Holder:     certificate.Name,
					Identifier: certificate.Identifier,
					Issuer:     certificate.IssuerName,
					NotAfter:   notAfter,
					SelfSigned: certificate.SelfSigned,
					Trusted:    certificate.Trusted,
					Qualified:  certificate.Qualified,
					Locality:   certificate.Locality,
				},
			})
		}
	}
	return certificates, nil
}

// compile-time check.
var _ application.CardReader = CommandLineCardReader{}
