package infrastructure

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain/identity"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/pdffield"
)

// minimumLegibleSize is the smallest type a seal in a field may use, in
// points: the box of a field is the form's, and a seal scaled to a tiny one
// prints nothing a reader can read.
const minimumLegibleSize = 3.0

// signInField signs the PDF in its empty signature field request.Field,
// the seal drawn in the field's box unless the request is invisible. The
// CMS envelope is trebaruna's own (a PAdES baseline one: no signing-time
// attribute, the time is /M), timestamped for level T.
func (s *PadesSigner) signInField(ctx context.Context, request application.PadesRequest, keyPair KeyPair) ([]byte, error) {
	fields, err := pdffield.EmptyFields(request.Content)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(fields, func(field pdffield.Field) bool { return field.Name == request.Field })
	moment := request.SignedAt
	if moment.IsZero() {
		moment = time.Now()
	}

	var appearance *pdffield.Appearance
	if index >= 0 && !request.Invisible {
		field := fields[index]
		if typographyFor(field.Width(), field.Height()).timeSize < minimumLegibleSize {
			return nil, fmt.Errorf("the field %q (%.0fx%.0f pt) is too small for a legible seal; sign it without a seal with --invisible", field.Name, field.Width(), field.Height())
		}
		marks, err := layoutSeal(field.Width(), field.Height(), identity.FromCertificate(keyPair.Certificate), moment, request.Rubric)
		if err != nil {
			return nil, fmt.Errorf("the field %q (%.0fx%.0f pt): %w; sign it without a seal with --invisible", field.Name, field.Width(), field.Height(), err)
		}
		if appearance, err = marks.fieldAppearance(); err != nil {
			return nil, err
		}
	}

	envelope := func(signed []byte) ([]byte, error) {
		built, err := cms.Sign(cms.Request{
			Content:     signed,
			Certificate: keyPair.Certificate,
			Chain:       keyPair.Chain,
			Signer:      keyPair.Signer,
		})
		if err != nil {
			return nil, err
		}
		if !request.Level.NeedsTimestamp() {
			return built.DER, nil
		}
		digest, err := digestFor(built.SignatureValue, crypto.SHA256)
		if err != nil {
			return nil, err
		}
		response, err := s.timestamps.Token(ctx, digest, request.TimestampURL, request.TimestampUser, request.TimestampSecret)
		if err != nil {
			return nil, err
		}
		return built.WithTimestamp(response)
	}

	reserve := 8192
	for _, certificate := range keyPair.Certificates() {
		reserve += len(certificate.Raw)
	}
	if request.Level.NeedsTimestamp() {
		reserve += 12288
	}
	for attempt := 0; ; attempt++ {
		signed, err := pdffield.Sign(request.Content, request.Field, appearance, pdffield.Signature{
			Name:     keyPair.Name,
			Reason:   request.Reason,
			Location: request.Location,
			SignedAt: moment,
			Reserve:  reserve,
			Envelope: envelope,
		})
		if errors.Is(err, pdffield.ErrReserveTooSmall) && attempt < 2 {
			reserve *= 2
			continue
		}
		return signed, err
	}
}
