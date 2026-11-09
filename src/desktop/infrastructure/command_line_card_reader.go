package infrastructure

// No build tag: plain os/exec, tested by `make test` with a stand-in command.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
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
	// Store lists a software store (domain.StoreFirefox) or a remote service
	// (domain.StoreRemote) instead of the cards.
	Store string
	// Account is, for a remote service, how to reach it as the form says
	// when the list is read.
	Account func() domain.RemoteAccount
}

// Cards runs the command and flattens its slots into certificates.
func (r CommandLineCardReader) Cards(ctx context.Context) ([]domain.CardCertificate, error) {
	var stdout, stderr bytes.Buffer
	arguments := []string{"token", "--json"}
	var account domain.RemoteAccount
	switch r.Store {
	case domain.StoreFirefox:
		arguments = append(arguments, "--firefox")
	case domain.StoreRemote:
		account = r.Account()
		if strings.TrimSpace(account.Address) == "" {
			// Nothing to ask yet: the list waits for the service's address.
			return nil, nil
		}
		arguments = append(arguments, remoteArguments(account, "")...)
	}
	command := exec.CommandContext(ctx, r.BinaryPath, arguments...)
	command.Env = append(os.Environ(), remoteEnvironment(account)...)
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
				Credential     string `json:"credential"`
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
				Store:          r.Store,
				Credential:     certificate.Credential,
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
