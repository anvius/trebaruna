package infrastructure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	"codeberg.org/simplicer/firma-it/src/signing/domain"
	"codeberg.org/simplicer/firma-it/src/signing/domain/identity"
	"codeberg.org/simplicer/firma-it/src/signing/infrastructure/dss"
	verificationdomain "codeberg.org/simplicer/firma-it/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/firma-it/src/verification/infrastructure"
	"github.com/digitorus/pdf"
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
//
// Levels that embed revocation are produced in two steps: pdfsign signs, then
// this adapter appends a /DSS dictionary in an incremental update. The library
// has no /DSS writer (its only revocation path is the Adobe attribute that ETSI
// EN 319 142-1 forbids for PAdES), but it does not need one: the store lives
// outside the signature.
func (s *PadesSigner) SignPades(ctx context.Context, request application.PadesRequest) ([]byte, error) {
	if request.Level.EmbedsRevocation() && !request.EmbedRevocation {
		return nil, fmt.Errorf(
			"%s needs embedded revocation (DSS) and a source for it.\n"+
				"  options:\n"+
				"    --level lt --online-revocation   query OCSP and embed the answers in /DSS\n"+
				"    --level t                        sign PAdES-B-T (timestamp, no DSS)",
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

	signed := output.Bytes()
	if !request.Level.EmbedsRevocation() || !request.EmbedRevocation {
		return signed, nil
	}

	// PAdES B-LT: the signature is complete at this point, so the validation
	// material goes in a second, appended update that leaves its bytes intact.
	return s.embedRevocation(ctx, signed, keyPair)
}

// embedRevocation collects status data and appends it as a /DSS dictionary.
//
// Every answer is obtained over the network, so this runs only when the caller
// asked for it. A certificate without a responder contributes nothing and is
// skipped: a /DSS with a hole in it is worse than no /DSS, because a validator
// reads it as complete.
func (s *PadesSigner) embedRevocation(
	ctx context.Context,
	signed []byte,
	keyPair KeyPair,
) ([]byte, error) {
	checker := verificationinfra.NewOCSPChecker()

	var (
		certificates []*x509.Certificate
		responses    [][]byte
		warnings     []string
	)

	chain := keyPair.Certificates()
	if len(chain) == 0 {
		return nil, fmt.Errorf("the signer carries no certificate chain to embed")
	}
	certificates = append(certificates, chain...)

	for index, certificate := range chain {
		issuer := chain[0]
		if index+1 < len(chain) {
			issuer = chain[index+1]
		}
		if index == len(chain)-1 {
			// The root revokes itself by definition; nothing to ask.
			break
		}

		status := checker.Check(ctx, certificate, issuer)
		switch {
		case status.IsRevoked():
			return nil, fmt.Errorf(
				"refusing to sign: the certificate for %q is revoked since %s",
				certificate.Subject.CommonName, status.RevokedAt.Format(time.RFC3339))
		case status.Status == verificationdomain.RevocationGood && len(status.RawResponse) > 0:
			responses = append(responses, status.RawResponse)
		default:
			warnings = append(warnings, fmt.Sprintf("%s: %s",
				certificate.Subject.CommonName, status.Reason))
		}
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf(
			"no revocation answer could be obtained, so %s cannot embed a complete /DSS:\n  %s",
			"PAdES B-LT", strings.Join(warnings, "\n  "))
	}

	// The VRI key is the uppercase hex SHA-1 of the signature value, which is how
	// a validator matches this material to this signature.
	key, err := signatureValueDigest(signed)
	if err != nil {
		return nil, err
	}

	updated, err := dss.Append(signed, dss.Validation{
		Certificates:  certificates,
		OCSPResponses: responses,
		VRI: []dss.VRIEntry{{
			Key:           key,
			Certificates:  certificates,
			OCSPResponses: responses,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("append the /DSS dictionary: %w", err)
	}
	return updated, nil
}

// signatureValueDigest returns the SHA-1 of the first signature's /Contents, in
// the uppercase hex form the VRI dictionary requires.
//
// EN 319 142-1 keys the VRI entry by the digest of the signature value, not of
// the whole CMS container, so the /Contents string is read from the document and
// hashed as it stands.
func signatureValueDigest(signed []byte) (string, error) {
	reader, err := pdf.NewReader(bytes.NewReader(signed), int64(len(signed)))
	if err != nil {
		return "", fmt.Errorf("reopen the signed PDF: %w", err)
	}

	contents, err := firstSignatureContents(reader)
	if err != nil {
		return "", err
	}

	digest := sha1.Sum(contents)
	return strings.ToUpper(hex.EncodeToString(digest[:])), nil
}

// firstSignatureContents walks the AcroForm fields looking for /Contents.
func firstSignatureContents(reader *pdf.Reader) ([]byte, error) {
	fields := reader.Trailer().Key("Root").Key("AcroForm").Key("Fields")
	for index := 0; index < fields.Len(); index++ {
		value := fields.Index(index).Key("V")
		if value.Kind() != pdf.Dict {
			continue
		}
		raw := value.Key("Contents").RawString()
		if raw == "" {
			continue
		}
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("the signed PDF carries no signature value")
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
