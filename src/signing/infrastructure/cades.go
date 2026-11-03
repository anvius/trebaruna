package infrastructure

import (
	"context"
	"crypto"
	"fmt"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	"codeberg.org/simplicer/firma-it/src/signing/domain"
	"codeberg.org/simplicer/firma-it/src/signing/infrastructure/cms"
)

// CadesSigner produces .p7m files: CMS SignedData with embedded content.
//
// It uses the local cms package rather than a CMS library because CAdES-T
// requires attaching an unsigned attribute after the signature value exists.
type CadesSigner struct {
	timestamps Timestamper
}

// NewCadesSigner wires the CMS adapter.
func NewCadesSigner(timestamps Timestamper) *CadesSigner {
	return &CadesSigner{timestamps: timestamps}
}

// SignCades builds the CMS container.
//
// Content is embedded, not detached, because that is what .p7m means in
// Italian practice.
func (s *CadesSigner) SignCades(ctx context.Context, request application.CadesRequest) ([]byte, error) {
	keyPair, err := LoadKeyPair(request.Signer)
	if err != nil {
		return nil, err
	}

	signature, err := cms.Sign(cms.Request{
		Content:            request.Content,
		Certificate:        keyPair.Certificate,
		Chain:              keyPair.Chain,
		Signer:             keyPair.Signer,
		EmbeddedContent:    true,
		IncludeSigningTime: true,
	})
	if err != nil {
		return nil, err
	}

	if !request.Level.NeedsTimestamp() {
		return signature.DER, nil
	}
	if s.timestamps == nil || request.TimestampURL == "" {
		return nil, fmt.Errorf("level %s needs a timestamp authority: pass --tsa <url>", request.Level)
	}

	// RFC 3161 timestamps the signature value, which is why the CMS must be
	// built first and completed afterwards.
	// RFC 3161 timestamps a digest: the imprint must be the digest of the
	// signature value, computed here so the token is verifiable by any tool.
	signatureDigest, err := digestFor(signature.SignatureValue, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	response, err := s.timestamps.Token(
		ctx, signatureDigest, request.TimestampURL,
		request.TimestampUser, request.TimestampSecret,
	)
	if err != nil {
		return nil, err
	}

	return signature.WithTimestamp(response)
}

// compile-time proof that the adapter satisfies the port.
var _ application.CadesSigner = (*CadesSigner)(nil)
var _ = domain.Cades
