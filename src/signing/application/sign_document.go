package application

import (
	"context"
	"fmt"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/domain"
)

// SignDocument is the single use case of the signing slice.
//
// It reads the document, delegates to the adapter that matches the requested
// format, and writes the artefact. All decisions about *what* to produce live
// here; all decisions about *how* live in the adapters.
type SignDocument struct {
	files    FileStore
	clock    Clock
	identity IdentityResolver
	cades    CadesSigner
	pades    PadesSigner
	xades    XadesSigner
}

// NewSignDocument wires the use case. Every adapter is optional until used:
// a caller that only signs PDFs does not need an XAdES adapter.
func NewSignDocument(
	files FileStore, clock Clock, identity IdentityResolver,
	cades CadesSigner, pades PadesSigner, xades XadesSigner,
) *SignDocument {
	return &SignDocument{
		files: files, clock: clock, identity: identity,
		cades: cades, pades: pades, xades: xades,
	}
}

// Request describes one signature operation.
type Request struct {
	Document   domain.Document
	Format     domain.Format
	Level      domain.Level
	Signer     domain.Signer
	OutputPath string
	Placement  domain.SealPlacement
	Placements []domain.SealPlacement
	// SignedAt is the single instant used for both the stamp and the report, so
	// the document and the JSON cannot disagree about when it was signed.
	SignedAt        time.Time
	Reason          string
	Location        string
	TimestampURL    string
	TimestampUser   string
	TimestampSecret string
	Enveloping      bool
	// EmbedRevocation asks for PAdES B-LT: the signature plus a /DSS dictionary
	// carrying the status answers. It reaches the network, so it is opt-in.
	EmbedRevocation bool
}

// Execute performs the signature and returns the produced artefact.
func (u *SignDocument) Execute(ctx context.Context, request Request) (Artefact, error) {
	if err := u.validate(request); err != nil {
		return Artefact{}, err
	}

	content, err := u.files.Read(request.Document.Path())
	if err != nil {
		return Artefact{}, fmt.Errorf("read document %s: %w", request.Document.Path(), err)
	}

	identity := Identity{}
	if u.identity != nil {
		resolved, err := u.identity.Resolve(request.Signer)
		if err != nil {
			return Artefact{}, err
		}
		identity = resolved
	}

	output := request.OutputPath
	if output == "" {
		output = request.Document.SignedName(request.Format)
	}

	// The instant is captured once and reused: two calls to the clock can land on
	// different seconds, which makes the report disagree with the stamp.
	signedAt := u.clock.Now()

	signed, err := u.sign(ctx, request.WithSignedAt(signedAt), content)
	if err != nil {
		return Artefact{}, err
	}

	if err := u.files.Write(output, signed); err != nil {
		return Artefact{}, fmt.Errorf("write signed document %s: %w", output, err)
	}

	return Artefact{
		Path:       output,
		Format:     request.Format,
		Level:      request.Level,
		Size:       len(signed),
		SignedAt:   signedAt,
		SignerName: request.Signer.Name(),
		// Only a PDF carries a visible seal: reporting one for CAdES or XAdES
		// would be a lie the caller could act on.
		SealCount:  sealCount(request),
		HasSeal:    sealCount(request) > 0,
		SelfSigned: identity.SelfSigned,
	}, nil
}

// validate applies guard clauses so the adapters receive a coherent request.
func (u *SignDocument) validate(request Request) error {
	if !request.Document.Supports(request.Format) {
		return fmt.Errorf("%w: %s cannot hold a %s signature",
			domain.ErrUnsupportedFormat, request.Document.Extension(), request.Format)
	}

	if request.Level.NeedsTimestamp() && request.TimestampURL == "" {
		return fmt.Errorf("level %s needs a timestamp authority: pass --tsa <url>", request.Level)
	}

	switch request.Format {
	case domain.Cades:
		if u.cades == nil {
			return fmt.Errorf("no CAdES adapter configured")
		}
	case domain.Pades:
		if u.pades == nil {
			return fmt.Errorf("no PAdES adapter configured")
		}
	case domain.Xades:
		if u.xades == nil {
			return fmt.Errorf("no XAdES adapter configured")
		}
	default:
		return fmt.Errorf("%w: %q", domain.ErrUnsupportedFormat, request.Format)
	}

	return nil
}

// sign dispatches to the adapter that owns the format.
//
// The second return value reports whether the signing certificate is
// self-signed. Callers must surface it: a self-signed signature is valid
// cryptography but carries no third-party trust, and hiding that would mislead.
func (u *SignDocument) sign(ctx context.Context, request Request, content []byte) ([]byte, error) {
	switch request.Format {
	case domain.Cades:
		signed, err := u.cades.SignCades(ctx, CadesRequest{
			Content:         content,
			Signer:          request.Signer,
			Level:           request.Level,
			EmbedRevocation: request.EmbedRevocation,
			TimestampURL:    request.TimestampURL,
			TimestampUser:   request.TimestampUser,
			TimestampSecret: request.TimestampSecret,
		})
		return signed, err

	case domain.Pades:
		signed, err := u.pades.SignPades(ctx, PadesRequest{
			Content:         content,
			Signer:          request.Signer,
			Level:           request.Level,
			EmbedRevocation: request.EmbedRevocation,
			Placement:       request.Placement,
			Placements:      sealPlacements(request),
			SignedAt:        request.SignedAt,
			Reason:          request.Reason,
			Location:        request.Location,
			TimestampURL:    request.TimestampURL,
			TimestampUser:   request.TimestampUser,
			TimestampSecret: request.TimestampSecret,
		})
		return signed, err

	case domain.Xades:
		signed, err := u.xades.SignXades(ctx, XadesRequest{
			Content:         content,
			Signer:          request.Signer,
			Level:           request.Level,
			EmbedRevocation: request.EmbedRevocation,
			Enveloping:      request.Enveloping,
			TimestampURL:    request.TimestampURL,
			TimestampUser:   request.TimestampUser,
			TimestampSecret: request.TimestampSecret,
		})
		return signed, err
	}

	return nil, fmt.Errorf("%w: %q", domain.ErrUnsupportedFormat, request.Format)
}

// SystemClock is the production Clock.
type SystemClock struct{}

// Now returns the current local time.
func (SystemClock) Now() time.Time { return time.Now() }

// sealPlacements returns the stamps to draw, folding the single-placement field
// into the list so callers of the old shape keep working.
func sealPlacements(request Request) []domain.SealPlacement {
	if len(request.Placements) > 0 {
		return request.Placements
	}
	if request.Placement.IsZero() {
		return nil
	}
	return []domain.SealPlacement{request.Placement}
}

// sealCount reports how many visible marks the artefact carries.
func sealCount(request Request) int {
	if request.Format != domain.Pades {
		return 0
	}
	return len(sealPlacements(request))
}

// WithSignedAt returns a copy carrying the signing instant.
func (r Request) WithSignedAt(moment time.Time) Request {
	r.SignedAt = moment
	return r
}
