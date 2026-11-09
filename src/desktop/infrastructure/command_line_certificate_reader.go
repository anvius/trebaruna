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
	"time"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// CommandLineCertificateReader describes a certificate by running
// `trebaruna certificate --json`, which already checks the issuer against the
// trusted lists: the window shows the same verdict the command prints.
type CommandLineCertificateReader struct {
	BinaryPath string
}

// Read runs the command for one file.
func (r CommandLineCertificateReader) Read(ctx context.Context, file domain.CertificateFile) (domain.CertificateSummary, error) {
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, r.BinaryPath, "certificate", file.Path, "--json")
	command.Env = append(os.Environ(), "TREBARUNA_PASSPHRASE="+file.Passphrase)
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if locked(stderr.String()) {
			return domain.CertificateSummary{}, domain.Problem{Code: domain.ProblemLockedCertificate}
		}
		return domain.CertificateSummary{}, errors.New(meaningfulLine(stderr.String(), stdout.String(), err))
	}

	var printed struct {
		Certificates []struct {
			Name       string `json:"name"`
			Identifier string `json:"identifier"`
			IssuerName string `json:"issuer_name"`
			NotAfter   string `json:"not_after"`
			SelfSigned bool   `json:"self_signed"`
			Trusted    bool   `json:"trusted"`
			Qualified  bool   `json:"qualified"`
			Locality   string `json:"locality"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		return domain.CertificateSummary{}, fmt.Errorf("the certificate command printed an unreadable answer: %w", err)
	}
	if len(printed.Certificates) == 0 {
		return domain.CertificateSummary{}, fmt.Errorf("%s contains no certificate", file.Path)
	}

	// The signing certificate comes first; the rest is its chain.
	leaf := printed.Certificates[0]
	notAfter, err := time.Parse(time.RFC3339, leaf.NotAfter)
	if err != nil {
		return domain.CertificateSummary{}, fmt.Errorf("unreadable expiry %q: %w", leaf.NotAfter, err)
	}
	return domain.CertificateSummary{
		Holder:     leaf.Name,
		Identifier: leaf.Identifier,
		Issuer:     leaf.IssuerName,
		NotAfter:   notAfter,
		SelfSigned: leaf.SelfSigned,
		Trusted:    leaf.Trusted,
		Qualified:  leaf.Qualified,
		Locality:   leaf.Locality,
	}, nil
}

// compile-time check.
var _ application.CertificateReader = CommandLineCertificateReader{}
