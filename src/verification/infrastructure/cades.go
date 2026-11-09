package infrastructure

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/publickey"
	"codeberg.org/simplicer/trebaruna/src/verification/application"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// CadesVerifier verifies CAdES containers (.p7m).
//
// The library exposes signed attributes but not unsigned ones, and the RFC 3161
// token lives in unsignedAttrs. Rather than reparse the whole structure by hand,
// the token is located in the raw DER and handed to the timestamp package, which
// does understand it. That keeps the parsing risk confined to finding an offset.
type CadesVerifier struct {
	// contentPath is the document a detached signature signs.
	contentPath string
	// signedBytes, when set, is that document already read: the byte ranges
	// a PDF signature signs.
	signedBytes []byte
	// Roots is the trusted root pool. Nil tells the library to use its own
	// defaults, which means "do not trust the embedded certificates".
	Roots *x509.CertPool
	// Now is the evaluation instant, injected for tests.
	Now time.Time
	// Anchors are the raw certificates the trust list published.
	//
	// The pool alone is not enough. A qualified trust list publishes the
	// authority that issues qualified certificates, and that authority is
	// usually an intermediate rather than a root. Adding it to the roots pool
	// is the only way to reach it, because the certificate it signed may not be
	// in the container.
	//
	// The raw certificates are needed because x509.CertPool cannot be
	// enumerated.
	Anchors []*x509.Certificate
}

// NewCadesVerifier builds the adapter.
// WithContent checks a detached signature against the document at path.
func (v *CadesVerifier) WithContent(path string) application.DocumentExtractor {
	clone := *v
	clone.contentPath = path
	return &clone
}

func NewCadesVerifier() *CadesVerifier {
	return &CadesVerifier{Now: time.Now()}
}

// WithAnchors returns a copy that validates chains against the given pools.
//
// It returns the application layer's extractor, not the local interface: the two
// are nominally distinct types, so a local return type makes the use case's type
// assertion fail and every trust list is silently ignored.
func (v *CadesVerifier) WithAnchors(roots, intermediates *x509.CertPool) application.DocumentExtractor {
	clone := *v
	clone.Roots = roots
	// The pool is not stored separately: pkcs7 already adds every certificate
	// travelling in the container to its intermediate pool, which is where the
	// listing publishes them too.
	_ = intermediates
	return &clone
}

// WithAnchorCertificates also keeps the raw certificates of the trust list.
//
// This is what makes a container that chains to a published authority verify.
// The raw certificates are needed because x509.CertPool cannot be enumerated.
func (v *CadesVerifier) WithAnchorCertificates(roots, intermediates *x509.CertPool, anchors []*x509.Certificate) application.DocumentExtractor {
	clone := v.WithAnchors(roots, intermediates).(*CadesVerifier)
	publickey.Complete(anchors...)
	clone.Anchors = anchors
	return clone
}

// rootsWithAnchors returns the pool the chain is verified against.
//
// Every trust-list certificate is added as a root. A qualified trust list
// publishes the authority that issues qualified certificates, and that authority
// is normally an intermediate rather than a root; treating it as a root is
// trusting the list's own statement about who it vouches for.
func (v *CadesVerifier) rootsWithAnchors() *x509.CertPool {
	if len(v.Anchors) == 0 {
		return v.Roots
	}
	if v.Roots != nil {
		for _, certificate := range v.Anchors {
			v.Roots.AddCert(certificate)
		}
		return v.Roots
	}
	pool := x509.NewCertPool()
	for _, certificate := range v.Anchors {
		pool.AddCert(certificate)
	}
	return pool
}

// Extract verifies a CMS container and returns one report.
func (v *CadesVerifier) Extract(path string) ([]domain.SignerReport, error) {
	if err := FileExists(path); err != nil {
		return nil, err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	// .p7m files also arrive as PEM or bare Base64; the rest of the checks
	// read the binary form.
	reports, err := v.extractEnvelope(CMSBytes(content))
	if err != nil {
		return nil, fmt.Errorf("%q: %w", path, err)
	}
	return reports, nil
}

// envelopeReports verifies an envelope against the bytes it signs, both in
// memory: a PDF signature is a detached CMS over its byte ranges.
func (v *CadesVerifier) envelopeReports(envelope, signed []byte) ([]domain.SignerReport, error) {
	clone := *v
	clone.contentPath, clone.signedBytes = "", signed
	return clone.extractEnvelope(envelope)
}

// hasDetached reports whether the document a detached signature signs is
// available.
func (v *CadesVerifier) hasDetached() bool {
	return v.contentPath != "" || v.signedBytes != nil
}

// detachedContent reads the document a detached signature signs.
func (v *CadesVerifier) detachedContent() ([]byte, error) {
	if v.signedBytes != nil {
		return v.signedBytes, nil
	}
	content, err := os.ReadFile(v.contentPath)
	if err != nil {
		return nil, fmt.Errorf("read the signed document %q: %w", v.contentPath, err)
	}
	return content, nil
}

// extractEnvelope verifies a CMS envelope in its binary form.
func (v *CadesVerifier) extractEnvelope(content []byte) ([]domain.SignerReport, error) {
	parsed, err := pkcs7.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("parse CMS: %w", err)
	}

	// Several signatures, or counter-signatures, go through the tree path,
	// which checks each node on its own.
	tree, treeErr := parseSignatureTree(content, nil)
	if treeErr == nil && tree.isTree() {
		if len(tree.content) == 0 && v.hasDetached() {
			if tree.content, err = v.detachedContent(); err != nil {
				return nil, err
			}
		}
		return v.extractTree(tree)
	}

	if len(parsed.Signers) != 1 {
		return nil, fmt.Errorf("CMS verification currently requires exactly one signer; found %d", len(parsed.Signers))
	}

	report := domain.SignerReport{
		FieldName: "CMS",
		Format:    "CAdES",
	}

	// A detached signature (.p7s) carries no content: the document it signs
	// comes from beside it. Without that document the bytes cannot be compared,
	// which is "unknown", never "altered" (ADR-0005).
	detached := len(parsed.Content) == 0
	if detached && v.hasDetached() {
		external, err := v.detachedContent()
		if err != nil {
			return nil, err
		}
		parsed.Content = external
		if v.contentPath != "" {
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "content.detached",
				Status:  domain.StatusGood,
				Message: "detached signature checked against the document beside it",
				Detail:  v.contentPath,
			})
		}
	}

	// Integrity: the detached/embedded content must still match the digest.
	if detached && !v.hasDetached() {
		report.Integrity = domain.StatusUnknown
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "content.missing",
			Status:  domain.StatusUnknown,
			Message: "detached signature: the signed document is needed to compare its bytes",
		})
	} else if err := verifyContent(parsed, tree, treeErr); errors.Is(err, errUnsupportedSignature) {
		report.Integrity = domain.StatusUnknown
		report.Findings = append(report.Findings, unverifiableFinding(err))
	} else if err != nil {
		report.Integrity = domain.StatusBad
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.modified",
			Status:  domain.StatusBad,
			Message: "the signed content does not match the signature",
			Detail:  err.Error(),
		})
	} else {
		report.Integrity = domain.StatusGood
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.intact",
			Status:  domain.StatusGood,
			Message: "the signed content is unaltered",
		})
	}

	signer := parsed.GetOnlySigner()
	if treeErr == nil && len(tree.signers) == 1 {
		describeESSCertificate(essCertificateDigests(tree.signers[0].SignedAttrs), signer, &report)
	}
	describeCertificate(signer, &report)

	// The issuer travels with the container, so a revocation query can be built
	// later without asking the user for anything.
	report.Revocation.Certificate = signer
	report.Revocation.Issuer = issuerFromSet(parsed.Certificates, signer)

	v.describeTime(content, parsed, &report)
	if treeErr == nil && len(tree.signers) == 1 {
		describeArchiveTimeStamps(tree.der, 0, tree.signers[0].UnsignedAttrs, parsed.Content, &report)
	}

	// The chain is validated at the proven signing time, not at the wall clock.
	// A certificate valid when the signature was made but expired since must not
	// turn into an untrusted issuer: that is the whole point of a timestamp.
	if signer != nil {
		switch {
		case report.SelfSigned:
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "certificate.self_signed",
				Status:  domain.StatusWarn,
				Message: "the certificate is self-signed: valid cryptography, no third-party trust",
			})
		case v.chainOf(signer, parsed.Certificates, chainInstant(&report, v.Now)) == nil:
			report.CertificateStatus = domain.StatusGood
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "certificate.trusted",
				Status:  domain.StatusGood,
				Message: "the issuer is a recognised authority",
			})
		default:
			report.CertificateStatus = domain.StatusUnknown
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "certificate.untrusted_issuer",
				Status:  domain.StatusUnknown,
				Message: "the issuer is not in any trusted list",
			})
		}
	}

	report.Trust = trustFromReport(report)
	return []domain.SignerReport{report}, nil
}

// issuerFromSet finds the certificate that signed the leaf among those the
// container carries.
func issuerFromSet(certificates []*x509.Certificate, leaf *x509.Certificate) *x509.Certificate {
	if leaf == nil {
		return nil
	}
	for _, candidate := range certificates {
		if candidate == nil || candidate.Equal(leaf) {
			continue
		}
		if bytes.Equal(candidate.RawSubject, leaf.RawIssuer) {
			return candidate
		}
	}
	return nil
}

// chainInstant picks the moment the chain must have been valid at.
//
// A verified timestamp is evidence; the claimed signing time is not. Falling back
// to "now" only happens when neither exists, which is the case for a bare
// CAdES-BES whose signer asserted nothing.
func chainInstant(report *domain.SignerReport, fallback time.Time) time.Time {
	if report.Timestamped && !report.SignedAt.IsZero() {
		return report.SignedAt
	}
	if fallback.IsZero() {
		return time.Now()
	}
	return fallback
}

// verifyContent checks the signature against the carried content: through
// the CMS library, or here for RSASSA-PSS, which the library does not
// implement. What neither implements is errUnsupportedSignature.
func verifyContent(parsed *pkcs7.PKCS7, tree signatureTree, treeErr error) error {
	if treeErr == nil && len(tree.signers) == 1 && isPSS(tree.signers[0].SignatureAlgorithm) {
		return verifyNode(tree.signers[0], parsed.GetOnlySigner(), parsed.Content)
	}
	// VerifyWithOpts with nil Roots checks cryptography without conflating
	// current certificate validity and content integrity.
	err := parsed.VerifyWithOpts(x509.VerifyOptions{CurrentTime: time.Now()})
	if err != nil && unsupportedByLibrary(err) {
		return fmt.Errorf("%w: %v", errUnsupportedSignature, err)
	}
	return err
}

// unverifiableFinding reports a signature trebaruna cannot check.
func unverifiableFinding(err error) domain.Finding {
	return domain.Finding{
		Code:    "signature.unverifiable",
		Status:  domain.StatusUnknown,
		Message: "the signature uses something trebaruna cannot check",
		Detail:  err.Error(),
	}
}

// No CMS timestamp is accepted as authoritative until its signature, imprint
// binding to the SignerInfo signature value and TSA trust chain are validated.
func (v *CadesVerifier) describeTime(content []byte, parsed *pkcs7.PKCS7, report *domain.SignerReport) {
	if claimed, err := signedSigningTime(parsed); err == nil && !claimed.IsZero() {
		report.SignedAt = claimed
	}

	tokenDER := findTimeStampToken(content)
	if tokenDER == nil {
		return
	}
	describeToken(tokenDER, firstSignerSignatureValue(content), report)
}

// describeToken checks an RFC 3161 token against the signature value it must
// cover and records what it proves.
func describeToken(tokenDER, signatureValue []byte, report *domain.SignerReport) {
	token, err := timestamp.Parse(tokenDER)
	if err != nil {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the timestamp token cannot be parsed",
			Detail:  err.Error(),
		})
		return
	}

	// The binding is what turns "a token exists" into evidence: the imprint must
	// be the digest of THIS signature value, otherwise the token covers another
	// signature and proves nothing about this one.
	if !tokenCovers(token, signatureValue) {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the timestamp belongs to a different signature",
		})
		return
	}

	report.SignedAt = token.Time
	report.Timestamped = true

	facts := ReadTimestamp(token)
	report.TimestampEvidence = domain.TimestampEvidence{
		Bound:                   true,
		CertificateCanTimestamp: facts.CanTimestamp,
		CertificateIssuerDN:     facts.SignerIssuerDN,
		Certificate:             facts.Signer,
	}
	if facts.Signer != nil {
		report.TimestampAuthority = facts.Signer.Subject.CommonName
	}

	// The imprint matches, so the seal covers this signature. Whether the sealer
	// is a qualified authority is a separate question that needs the trust list;
	// the use case answers it and replaces these findings.
	report.Findings = append(report.Findings, domain.Finding{
		Code:    "timestamp.bound",
		Status:  domain.StatusGood,
		Message: "the timestamp is bound to this signature",
	})
	if !facts.CanTimestamp {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.not_timestamping_certificate",
			Status:  domain.StatusWarn,
			Message: "the timestamp certificate lacks the timeStamping key usage",
		})
	}
}

// tokenBindsToSignature compares the token imprint with the digest of the
// signature value it claims to cover.
func tokenBindsToSignature(token *timestamp.Timestamp, cms []byte) bool {
	return tokenCovers(token, firstSignerSignatureValue(cms))
}

// tokenCovers reports whether the token's imprint is the digest of signatureValue.
func tokenCovers(token *timestamp.Timestamp, signatureValue []byte) bool {
	if len(signatureValue) == 0 || !token.HashAlgorithm.Available() {
		return false
	}

	hasher := token.HashAlgorithm.New()
	hasher.Write(signatureValue)
	return bytes.Equal(hasher.Sum(nil), token.HashedMessage)
}

// firstSignerSignatureValue reads the EncryptedDigest of the first SignerInfo.
//
// The pkcs7 library keeps signerInfo unexported, so the value is re-read from
// the DER with the same approach used to locate the token.
func firstSignerSignatureValue(cms []byte) []byte {
	fields, err := splitDerSequence(cms)
	if err != nil || len(fields) < 2 {
		return nil
	}

	// ContentInfo.content is [0] EXPLICIT SignedData.
	signedData, err := unwrapExplicit(fields[1])
	if err != nil {
		return nil
	}

	sequence, err := splitDerSequence(signedData)
	if err != nil || len(sequence) == 0 {
		return nil
	}

	// The last field of SignedData is the SET OF SignerInfo.
	signerInfos, err := splitDerSequence(sequence[len(sequence)-1])
	if err != nil || len(signerInfos) == 0 {
		return nil
	}

	signerInfo, err := splitDerSequence(signerInfos[0])
	if err != nil {
		return nil
	}

	// SignerInfo v1 fields, in order:
	//   1 version, 2 sid, 3 digestAlgorithm, 4 signedAttrs [0],
	//   5 signatureAlgorithm, 6 signature OCTET STRING, 7 unsignedAttrs [1].
	//
	// signedAttrs is a context tag, not a SEQUENCE, so the naive "first OCTET
	// STRING that is not the version" picks the messageDigest attribute nested
	// inside it and the imprint comparison fails on a perfectly valid token.
	// The signature is the field that follows the signature algorithm.
	const signatureAlgorithmIndex = 4
	signatureIndex := signatureAlgorithmIndex + 1
	if len(signerInfo) <= signatureIndex {
		return nil
	}

	signature := signerInfo[signatureIndex]
	if len(signature) < 2 || signature[0] != 0x04 {
		return nil
	}
	length, headerSize, ok := readLength(signature, 1)
	if !ok || 1+headerSize+length > len(signature) {
		return nil
	}
	return signature[1+headerSize : 1+headerSize+length]
}

// signedSigningTime reads the signingTime signed attribute.
func signedSigningTime(parsed *pkcs7.PKCS7) (time.Time, error) {
	var encoded time.Time
	err := parsed.UnmarshalSignedAttribute(oidSigningTimeAttribute, &encoded)
	return encoded, err
}

// trustFromReport reduces the findings into a level.
func trustFromReport(report domain.SignerReport) domain.TrustLevel {
	if report.Integrity == domain.StatusBad {
		return domain.TrustBroken
	}
	if report.SelfSigned {
		return domain.TrustUntrusted
	}
	if report.CertificateStatus == domain.StatusUnknown {
		return domain.TrustUntrusted
	}
	return domain.TrustAdvanced
}

// compile-time check.
var _ SignatureExtractor = (*CadesVerifier)(nil)

// FirstSignerSignatureValueForTest exposes the DER reader for tests that pin
// which field is the signature. Production callers use the verifier.
func FirstSignerSignatureValueForTest(cms []byte) []byte {
	return firstSignerSignatureValue(cms)
}
