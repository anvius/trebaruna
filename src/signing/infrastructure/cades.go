package infrastructure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"slices"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
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
		if !request.ContentDigest.IsZero() {
			return nil, fmt.Errorf("a digest is signed, not co- or counter-signed")
		}
		return s.addSignature(ctx, request, keyPair)
	}

	policy, err := policyAttributes(request.Policy)
	if err != nil {
		return nil, err
	}
	cmsRequest := cms.Request{
		Content:            request.Content,
		Certificate:        keyPair.Certificate,
		Chain:              keyPair.Chain,
		Signer:             keyPair.Signer,
		EmbeddedContent:    !request.Detached,
		IncludeSigningTime: true,
		ExtraAttributes:    policy,
	}
	if !request.ContentDigest.IsZero() {
		// The archive timestamp seals the content, which a digest is not.
		if request.Level.Archival() {
			return nil, fmt.Errorf("level %s seals the document, and only its digest is here", request.Level)
		}
		cmsRequest.Content, cmsRequest.EmbeddedContent = nil, false
		cmsRequest.Hash = map[string]crypto.Hash{"SHA256": crypto.SHA256, "SHA384": crypto.SHA384, "SHA512": crypto.SHA512}[request.ContentDigest.Algorithm()]
		cmsRequest.ContentDigest = request.ContentDigest.Value()
	}
	signature, err := cms.Sign(cmsRequest)
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
		return nil, needsRevocationSource(request.Level)
	}

	// The validation material covers the authority behind the signature
	// timestamp too, and goes where the baseline profile wants it: in
	// SignedData.certificates and SignedData.crls, not in the
	// certificate-values and revocation-values attributes, which make a
	// CAdES-LT the extended X-L form in EU DSS's eyes.
	tokens, err := cms.SignatureTimeStampTokens(signed)
	if err != nil {
		return nil, err
	}
	material, err := gatherValidationMaterial(ctx, keyPair, tokens, cadesIncomplete)
	if err != nil {
		return nil, err
	}
	withRevocation, err := cms.WithValidationData(signed, rawCertificates(material.certificates()), nil, material.responses)
	if err != nil {
		return nil, err
	}

	if !request.Level.Archival() {
		return withRevocation, nil
	}

	return s.withArchiveTimeStamp(ctx, withRevocation, request, 0, request.Content)
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
	signer int,
	content []byte,
) ([]byte, error) {
	if s.timestamps == nil || request.TimestampURL == "" {
		return nil, fmt.Errorf("level %s needs a timestamp authority: pass --tsa <url>", request.Level)
	}
	prefix, hashIndex, err := cms.ArchiveTimeStampV3Input(container, signer, content, crypto.SHA256)
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
	return cms.WithArchiveTimeStampV3(container, signer, tokenDER, hashIndex)
}

// needsRevocationSource refuses a level that embeds revocation without
// the network being allowed for it.
func needsRevocationSource(level domain.Level) error {
	return fmt.Errorf("%s needs embedded revocation and a source for it:\n"+
		"    --level lt --online-revocation   query OCSP and attach the answers", level)
}

// rawCertificates are the certificates as encoded.
func rawCertificates(certificates []*x509.Certificate) [][]byte {
	raw := make([][]byte, len(certificates))
	for index, certificate := range certificates {
		raw[index] = certificate.Raw
	}
	return raw
}

// cadesIncomplete is what a CAdES-LT without any revocation answer would
// leave incomplete.
const cadesIncomplete = "CAdES-LT cannot carry complete revocation information"

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

	if request.Level.EmbedsRevocation() && !request.EmbedRevocation {
		return nil, needsRevocationSource(request.Level)
	}
	// The timestamps already there are someone else's: only the ones the
	// added signature brings call for their authority's material.
	earlier, err := cms.AllSignatureTimeStampTokens(request.Content)
	if err != nil {
		return nil, err
	}

	var signed []byte
	if request.Cosign {
		signed, err = cms.Cosign(request.Content, request.DetachedContent, cmsRequest, stamp)
	} else {
		signed, _, err = cms.Countersign(request.Content, cmsRequest, cms.CountersignScope(request.Countersign), stamp)
	}
	if err != nil {
		return nil, err
	}
	if request.Level.EmbedsRevocation() {
		// The added signature's validation material, its chain's and the
		// authority's behind each timestamp it brought, in SignedData as
		// the baseline profile asks.
		tokens, err := cms.AllSignatureTimeStampTokens(signed)
		if err != nil {
			return nil, err
		}
		added := slices.DeleteFunc(tokens, func(token []byte) bool {
			return slices.ContainsFunc(earlier, func(old []byte) bool { return bytes.Equal(old, token) })
		})
		material, err := gatherValidationMaterial(ctx, keyPair, added, cadesIncomplete)
		if err != nil {
			return nil, err
		}
		if signed, err = cms.WithValidationData(signed, rawCertificates(material.certificates()), nil, material.responses); err != nil {
			return nil, err
		}
	}
	if !request.Level.Archival() {
		return signed, nil
	}
	return s.archiveAdded(ctx, signed, request)
}

// archiveAdded seals the signatures that changed with an archive timestamp
// (CAdES-LTA): the parallel signature added, or each signature that took
// counter-signatures, whose archive timestamp seals them with it.
func (s *CadesSigner) archiveAdded(ctx context.Context, signed []byte, request application.CadesRequest) ([]byte, error) {
	count, err := cms.SignerCount(signed)
	if err != nil {
		return nil, err
	}
	first := 0
	if request.Cosign {
		first = count - 1
	}
	for signer := first; signer < count; signer++ {
		if signed, err = s.withArchiveTimeStamp(ctx, signed, request, signer, request.DetachedContent); err != nil {
			return nil, err
		}
	}
	return signed, nil
}
