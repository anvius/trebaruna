package application

import (
	"context"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// CertificateReader opens a certificate file and describes it.
type CertificateReader interface {
	Read(ctx context.Context, file domain.CertificateFile) (domain.CertificateSummary, error)
}

// InspectCertificate is the use case behind the certificate card: as soon as
// the user picks a file and types its passphrase, the window says whose it is,
// who vouches for it and until when, instead of finding out at signing time.
type InspectCertificate struct {
	reader CertificateReader
}

// NewInspectCertificate wires the use case.
func NewInspectCertificate(reader CertificateReader) *InspectCertificate {
	return &InspectCertificate{reader: reader}
}

// Execute reads the certificate.
func (u *InspectCertificate) Execute(ctx context.Context, file domain.CertificateFile) (domain.CertificateSummary, error) {
	if strings.TrimSpace(file.Path) == "" {
		return domain.CertificateSummary{}, domain.Problem{Code: domain.ProblemMissingKey}
	}
	return u.reader.Read(ctx, file)
}
