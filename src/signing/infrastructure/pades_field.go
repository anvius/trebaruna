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

// signOwn writes a PDF signature the PDF library cannot: in an existing
// field, or with a policy.
func (s *PadesSigner) signOwn(ctx context.Context, request application.PadesRequest, keyPair KeyPair) ([]byte, error) {
	if request.Field != "" {
		return s.signInField(ctx, request, keyPair)
	}
	return s.signInNewField(ctx, request, keyPair)
}

// signingMoment is the request's instant, the stamp's and /M alike.
func signingMoment(request application.PadesRequest) time.Time {
	if request.SignedAt.IsZero() {
		return time.Now()
	}
	return request.SignedAt
}

// minimumLegibleSize is the smallest type a seal in a field may use, in
// points: the box of a field is the form's, and a seal scaled to a tiny one
// prints nothing a reader can read.
const minimumLegibleSize = 3.0

// signInField signs the PDF in its empty signature field request.Field,
// the seal drawn in the field's box unless the request is invisible.
func (s *PadesSigner) signInField(ctx context.Context, request application.PadesRequest, keyPair KeyPair) ([]byte, error) {
	fields, err := pdffield.EmptyFields(request.Content)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(fields, func(field pdffield.Field) bool { return field.Name == request.Field })
	moment := signingMoment(request)

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

	return s.signWithRoom(ctx, request, keyPair, func(signature pdffield.Signature) ([]byte, error) {
		return pdffield.Sign(request.Content, request.Field, appearance, signature)
	})
}

// signInNewField signs the PDF in a new field, with a seal at each
// placement or none: the PDF library's job, done here for what it cannot
// add to the signed attributes, a signature policy (PAdES-EPES).
func (s *PadesSigner) signInNewField(ctx context.Context, request application.PadesRequest, keyPair KeyPair) ([]byte, error) {
	placements, err := placeOnPages(request.Content, sealPlacementsOf(request))
	if err != nil {
		return nil, err
	}
	moment := signingMoment(request)
	holder := identity.FromCertificate(keyPair.Certificate)
	widgets := make([]pdffield.Widget, 0, len(placements))
	for _, placement := range placements {
		left, bottom, right, top := placement.Box()
		marks, err := layoutSeal(right-left, top-bottom, holder, moment, request.Rubric)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", placement.Page(), err)
		}
		appearance, err := marks.fieldAppearance()
		if err != nil {
			return nil, err
		}
		widgets = append(widgets, pdffield.Widget{Page: placement.Page(), Rect: [4]float64{left, bottom, right, top}, Appearance: appearance})
	}
	return s.signWithRoom(ctx, request, keyPair, func(signature pdffield.Signature) ([]byte, error) {
		return pdffield.SignNew(request.Content, widgets, signature)
	})
}

// envelope builds trebaruna's CMS envelope over the bytes a PDF signature
// covers: a PAdES baseline one (no signing-time attribute, the time is
// /M), with the policy given, timestamped for level T.
func (s *PadesSigner) envelope(ctx context.Context, request application.PadesRequest, keyPair KeyPair, policy []cms.Attribute) func([]byte) ([]byte, error) {
	return func(signed []byte) ([]byte, error) {
		built, err := cms.Sign(cms.Request{
			Content:         signed,
			Certificate:     keyPair.Certificate,
			Chain:           keyPair.Chain,
			Signer:          keyPair.Signer,
			ExtraAttributes: policy,
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
}

// signWithRoom signs with trebaruna's envelope, its room doubled when it
// does not fit.
func (s *PadesSigner) signWithRoom(ctx context.Context, request application.PadesRequest, keyPair KeyPair, sign func(pdffield.Signature) ([]byte, error)) ([]byte, error) {
	policy, err := policyAttributes(request.Policy)
	if err != nil {
		return nil, err
	}
	envelope := s.envelope(ctx, request, keyPair, policy)
	reserve := 8192
	for _, certificate := range keyPair.Certificates() {
		reserve += len(certificate.Raw)
	}
	if request.Level.NeedsTimestamp() {
		reserve += 12288
	}
	for attempt := 0; ; attempt++ {
		signed, err := sign(pdffield.Signature{
			Name:     keyPair.Name,
			Reason:   request.Reason,
			Location: request.Location,
			Password: request.Password,
			SignedAt: signingMoment(request),
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
