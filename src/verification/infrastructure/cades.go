package infrastructure

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"codeberg.org/anvius/pignus/src/verification/application"
	"codeberg.org/anvius/pignus/src/verification/domain"
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
	// Roots is the trusted root pool. Nil tells the library to use its own
	// defaults, which means "do not trust the embedded certificates".
	Roots *x509.CertPool
	// Now is the evaluation instant, injected for tests.
	Now time.Time
}

// NewCadesVerifier builds the adapter.
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

// Extract verifies a CMS container and returns one report.
func (v *CadesVerifier) Extract(path string) ([]domain.SignerReport, error) {
	if err := FileExists(path); err != nil {
		return nil, err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	parsed, err := pkcs7.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("parse CMS in %q: %w", path, err)
	}

	if len(parsed.Signers) != 1 {
		return nil, fmt.Errorf("CMS verification currently requires exactly one signer; found %d", len(parsed.Signers))
	}

	report := domain.SignerReport{
		FieldName: "CMS",
		Format:    "CAdES",
	}

	// Integrity: the detached/embedded content must still match the digest.
	if err := verifyContent(parsed); err != nil {
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
	describeCertificate(signer, &report)

	// The issuer travels with the container, so a revocation query can be built
	// later without asking the user for anything.
	report.Revocation.Certificate = signer
	report.Revocation.Issuer = issuerFromSet(parsed.Certificates, signer)

	v.describeTime(content, parsed, &report)

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
		case verifyCMSChain(parsed, v.Roots, chainInstant(&report, v.Now)) == nil:
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

// verifyContent checks the signature against the carried content.
func verifyContent(parsed *pkcs7.PKCS7) error {
	// VerifyWithOpts with nil Roots checks cryptography without conflating
	// current certificate validity and content integrity.
	return parsed.VerifyWithOpts(x509.VerifyOptions{CurrentTime: time.Now()})
}

func verifyCMSChain(parsed *pkcs7.PKCS7, roots *x509.CertPool, now time.Time) error {
	if roots == nil {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return err
		}
	}
	if now.IsZero() {
		now = time.Now()
	}
	return parsed.VerifyWithChainAtTime(roots, now)
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
	if !tokenBindsToSignature(token, content) {
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
	signatureValue := firstSignerSignatureValue(cms)
	if len(signatureValue) == 0 || token.HashAlgorithm.Available() == false {
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
