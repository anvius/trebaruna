package infrastructure

import (
	"context"
	"crypto"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
	"strings"
	"time"
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
// By default the content is embedded, because that is what .p7m means in
// Italian practice; a detached request leaves it out and the result is a
// .p7s that travels beside the document.
func (s *CadesSigner) SignCades(ctx context.Context, request application.CadesRequest) ([]byte, error) {
	keyPair, err := LoadKeyPair(request.Signer)
	if err != nil {
		return nil, err
	}
	defer keyPair.Close()
	if request.Cosign || request.Countersign != "" {
		return s.addSignature(ctx, request, keyPair)
	}

	policy, err := policyAttributes(request.Policy)
	if err != nil {
		return nil, err
	}
	signature, err := cms.Sign(cms.Request{
		Content:            request.Content,
		Certificate:        keyPair.Certificate,
		Chain:              keyPair.Chain,
		Signer:             keyPair.Signer,
		EmbeddedContent:    !request.Detached,
		IncludeSigningTime: true,
		ExtraAttributes:    policy,
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

	signed, err := signature.WithTimestamp(response)
	if err != nil {
		return nil, err
	}

	if !request.Level.EmbedsRevocation() {
		return signed, nil
	}
	if !request.EmbedRevocation {
		return nil, fmt.Errorf(
			"%s needs embedded revocation and a source for it:\n"+
				"    --level lt --online-revocation   query OCSP and attach the answers",
			request.Level)
	}

	withRevocation, err := s.withRevocationValues(ctx, signed, request, keyPair)
	if err != nil {
		return nil, err
	}

	if !request.Level.Archival() {
		return withRevocation, nil
	}

	return s.withArchiveTimeStamp(ctx, withRevocation, request)
}

// withArchiveTimeStamp adds the CAdES-LTA archive timestamp, an
// archive-time-stamp-v3 (ETSI EN 319 122-1, 5.5.3).
//
// The token seals the signed content, the signature and, through the hash
// index it carries, every certificate, revocation value and unsigned
// attribute the container holds now, the revocation material attached a
// moment ago included: what survives the responder and the CA disappearing.
func (s *CadesSigner) withArchiveTimeStamp(
	ctx context.Context,
	container []byte,
	request application.CadesRequest,
) ([]byte, error) {
	if s.timestamps == nil || request.TimestampURL == "" {
		return nil, fmt.Errorf("level %s needs a timestamp authority: pass --tsa <url>", request.Level)
	}
	prefix, hashIndex, err := cms.ArchiveTimeStampV3Input(container, 0, request.Content, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	digest, err := digestFor(append(prefix, hashIndex...), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	response, err := s.timestamps.Token(
		ctx, digest, request.TimestampURL,
		request.TimestampUser, request.TimestampSecret,
	)
	if err != nil {
		return nil, err
	}
	tokenDER, err := cms.ExtractToken(response)
	if err != nil {
		return nil, err
	}
	return cms.WithArchiveTimeStampV3(container, 0, tokenDER, hashIndex)
}

// withRevocationValues attaches the CAdES-LT revocation material.
//
// The attribute is unsigned, which is the point: the signature covers the document
// and the signed attributes, and the validation data rides beside them. Refusing to
// sign a revoked certificate is the same rule as in PAdES — producing a signature
// nobody can rely on wastes everyone's time.
func (s *CadesSigner) withRevocationValues(
	ctx context.Context,
	signed []byte,
	request application.CadesRequest,
	keyPair KeyPair,
) ([]byte, error) {
	checker := verificationinfra.NewOCSPChecker()

	chain := keyPair.Certificates()
	if len(chain) == 0 {
		return nil, fmt.Errorf("the signer carries no certificate chain to embed")
	}

	var responses [][]byte
	var warnings []string
	for index, certificate := range chain {
		if index+1 >= len(chain) {
			// The root revokes itself by definition.
			break
		}
		status := checker.Check(ctx, certificate, chain[index+1])
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
			"no revocation answer could be obtained, so CAdES-LT cannot carry a complete "+
				"RevocationValues attribute:\n  %s", strings.Join(warnings, "\n  "))
	}

	return cms.WithRevocationValuesFrom(signed, responses, nil)
}

// compile-time proof that the adapter satisfies the port.
var _ application.CadesSigner = (*CadesSigner)(nil)
var _ = domain.Cades

// policyAttributes is the signed attribute declaring the policy, if any.
func policyAttributes(policy domain.SignaturePolicy) ([]cms.Attribute, error) {
	if policy.IsZero() {
		return nil, nil
	}
	oid, ok := policy.OID()
	if !ok {
		return nil, fmt.Errorf("%w: %s", domain.ErrPolicyNotForFormat, policy.Identifier())
	}
	attribute, err := cms.PolicyAttribute(oid, policy.HashAlgorithm(), policy.Hash(), policy.Qualifier())
	if err != nil {
		return nil, err
	}
	return []cms.Attribute{attribute}, nil
}

// addSignature co-signs or counter-signs the envelope in request.Content.
func (s *CadesSigner) addSignature(ctx context.Context, request application.CadesRequest, keyPair KeyPair) ([]byte, error) {
	policy, err := policyAttributes(request.Policy)
	if err != nil {
		return nil, err
	}
	cmsRequest := cms.Request{
		Certificate:        keyPair.Certificate,
		Chain:              keyPair.Chain,
		Signer:             keyPair.Signer,
		IncludeSigningTime: true,
		ExtraAttributes:    policy,
	}

	var stamp cms.Stamper
	if request.Level.NeedsTimestamp() {
		if s.timestamps == nil || request.TimestampURL == "" {
			return nil, fmt.Errorf("level %s needs a timestamp authority: pass --tsa <url>", request.Level)
		}
		stamp = func(signatureValue []byte) ([]byte, error) {
			digest, err := digestFor(signatureValue, crypto.SHA256)
			if err != nil {
				return nil, err
			}
			return s.timestamps.Token(ctx, digest, request.TimestampURL, request.TimestampUser, request.TimestampSecret)
		}
	}

	if request.Cosign {
		return cms.Cosign(request.Content, request.DetachedContent, cmsRequest, stamp)
	}
	signed, _, err := cms.Countersign(request.Content, cmsRequest, cms.CountersignScope(request.Countersign), stamp)
	return signed, err
}
