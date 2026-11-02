package infrastructure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	"codeberg.org/simplicer/firma-it/src/signing/domain"
	"codeberg.org/simplicer/firma-it/src/signing/domain/identity"
	"github.com/digitorus/pdfsign"
)

// PadesSigner produces signed PDFs with pdfsign, adding the visible seal.
//
// pdfsign v1.0.0 supports PAdES B and B-T natively; B-LT and B-LTA return
// "signature format N is not currently supported". Rather than emit a file
// with the wrong profile, this adapter refuses and explains the alternative.
type PadesSigner struct {
	timestamps Timestamper
}

// NewPadesSigner wires the PDF adapter.
func NewPadesSigner(timestamps Timestamper) *PadesSigner {
	return &PadesSigner{timestamps: timestamps}
}

// SignPades signs the PDF and returns the new document bytes.
func (s *PadesSigner) SignPades(ctx context.Context, request application.PadesRequest) ([]byte, error) {
	if request.Level.EmbedsRevocation() {
		return nil, fmt.Errorf(
			"%s needs embedded revocation (DSS), and the PDF library does not support it yet.\n"+
				"  options:\n"+
				"    --level t          sign PAdES-B-T now (timestamp, no DSS)\n"+
				"    --level bes        sign PAdES-B\n"+
				"    post-process with: firma-it dss <file> --tsa <url>   (adds /DSS later)",
			request.Level,
		)
	}

	keyPair, err := LoadKeyPair(request.Signer)
	if err != nil {
		return nil, err
	}

	document, err := pdfsign.Open(bytes.NewReader(request.Content), int64(len(request.Content)))
	if err != nil {
		return nil, fmt.Errorf("open PDF: %w", err)
	}

	// Every stamp is built before Write because each carries the identity read
	// from the certificate, never a name typed into a form.
	stamps, sealErr := buildSeals(request, keyPair)
	if sealErr != nil {
		return nil, sealErr
	}

	builder := document.Sign(keyPair.Signer, keyPair.Certificate).
		Format(pdfFormatFor(request.Level)).
		Digest(crypto.SHA256).
		SignerName(keyPair.Name).
		Context(ctx)

	if request.Reason != "" {
		builder = builder.Reason(request.Reason)
	}
	if request.Location != "" {
		builder = builder.Location(request.Location)
	}
	if len(keyPair.Chain) > 0 {
		builder = builder.CertificateChains([][]*x509.Certificate{keyPair.Certificates()})
	}
	if request.Level.NeedsTimestamp() && request.TimestampURL != "" {
		builder = builder.Timestamp(request.TimestampURL)
		if request.TimestampUser != "" {
			builder = builder.TimestampAuth(request.TimestampUser, request.TimestampSecret)
		}
	}

	for _, stamp := range stamps {
		builder = builder.Appearance(stamp.appearance, stamp.lowerLeftX, stamp.lowerLeftY).Page(stamp.page)
	}

	var output bytes.Buffer
	if _, err := document.Write(&output); err != nil {
		return nil, fmt.Errorf("write signed PDF: %w", err)
	}
	return output.Bytes(), nil
}

// pdfFormatFor maps the domain level onto the library format.
func pdfFormatFor(level domain.Level) pdfsign.Format {
	if level.NeedsTimestamp() {
		return pdfsign.PAdES_B_T
	}
	return pdfsign.PAdES_B
}

// stamp is one drawn mark and where it goes.
type stamp struct {
	appearance             *pdfsign.Appearance
	page                   int
	lowerLeftX, lowerLeftY float64
}

// buildSeals renders one appearance per placement, all sharing the same
// cryptographic signature: several marks, one key, one verifiable value.
func buildSeals(request application.PadesRequest, keyPair KeyPair) ([]stamp, error) {
	placements := request.Placements
	if len(placements) == 0 && !request.Placement.IsZero() {
		placements = []domain.SealPlacement{request.Placement}
	}

	holder := identity.FromCertificate(keyPair.Certificate)
	moment := request.SignedAt
	if moment.IsZero() {
		// Direct callers (tests, future gRPC surface) may omit it; the stamp then
		// falls back to the wall clock rather than printing year one.
		moment = time.Now()
	}

	stamps := make([]stamp, 0, len(placements))
	for _, placement := range placements {
		lowerLeftX, lowerLeftY, upperRightX, upperRightY := placement.Box()
		width, height := upperRightX-lowerLeftX, upperRightY-lowerLeftY
		if width <= 0 || height <= 0 {
			return nil, fmt.Errorf("seal box on page %d is empty: %.1fx%.1f pt", placement.Page(), width, height)
		}

		appearance, err := DrawSeal(width, height, holder, moment)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", placement.Page(), err)
		}
		stamps = append(stamps, stamp{
			appearance: appearance,
			page:       placement.Page(),
			lowerLeftX: lowerLeftX,
			lowerLeftY: lowerLeftY,
		})
	}
	return stamps, nil
}

// compile-time check.
var _ application.PadesSigner = (*PadesSigner)(nil)
