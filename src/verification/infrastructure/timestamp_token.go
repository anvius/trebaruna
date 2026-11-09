package infrastructure

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/digitorus/timestamp"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// parseTimeStamp reads an RFC 3161 token and checks its signature: through
// the timestamp library or, for a token its authority signed with
// RSASSA-PSS, which the library's CMS code does not implement, here, the
// SignerInfo checked over the TSTInfo as any CMS signature (verifyNode).
func parseTimeStamp(der []byte) (*timestamp.Timestamp, error) {
	// A token's content is declared a TSTInfo (RFC 3161, 2.4.2). The
	// timestamp library reads any signed content that parses as one, so a
	// signature over other data passed for a timestamp.
	tree, treeErr := parseSignatureTree(der, nil)
	if treeErr == nil && !tree.contentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("the timestamp token does not carry a TSTInfo")
	}
	token, err := timestamp.Parse(der)
	if err == nil || !unsupportedByLibrary(err) {
		return token, err
	}
	if treeErr != nil || len(tree.signers) != 1 || !isPSS(tree.signers[0].SignatureAlgorithm) {
		return nil, err
	}
	signer := tree.signers[0]
	if !slices.ContainsFunc(tree.certificatesFor(signer.SID), func(certificate *x509.Certificate) bool {
		return verifyNode(signer, certificate, tree.content) == nil
	}) {
		return nil, fmt.Errorf("the timestamp's RSASSA-PSS signature does not verify")
	}
	return readTSTInfo(der, tree)
}

// timeStampReport judges a token that stands on its own (an ASiC
// timestamp, a PDF document timestamp): its signature, then whether its
// imprint is that of what it covers; its authority is named and checked
// like a signer. parsed is false when the token itself does not verify.
// The report's trust is left to the caller, who may check more.
func (v *CadesVerifier) timeStampReport(raw, covered []byte) (domain.SignerReport, bool) {
	var report domain.SignerReport
	token, err := parseTimeStamp(raw)
	if err != nil {
		report.Integrity = domain.StatusBad
		report.Findings = append(report.Findings, domain.Finding{Code: "timestamp.invalid", Status: domain.StatusBad,
			Message: "the timestamp cannot be parsed or does not verify", Detail: err.Error()})
		return report, false
	}
	report.SignedAt, report.Timestamped = token.Time, true
	if len(token.Certificates) > 0 {
		describeCertificate(token.Certificates[0], &report)
		v.describeIssuer(token.Certificates[0], token.Certificates, token.Time, &report)
	}
	if tokenCovers(token, covered) {
		report.Integrity = domain.StatusGood
		report.Findings = append(report.Findings, domain.Finding{Code: "signature.intact", Status: domain.StatusGood,
			Message: "the timestamped content is unaltered"})
	} else {
		report.Integrity = domain.StatusBad
		report.Findings = append(report.Findings, domain.Finding{Code: "signature.modified", Status: domain.StatusBad,
			Message: "the content changed after it was timestamped"})
	}
	return report, true
}

// timeStampedWithPSS reports a SignerInfo whose signature timestamp an
// authority signed with RSASSA-PSS, which the PDF library cannot read.
func timeStampedWithPSS(signer treeSignerInfo) bool {
	for _, token := range attributeValues(signer.UnsignedAttrs, oidAttributeTimestamp) {
		tree, err := parseSignatureTree(token, nil)
		if err == nil && len(tree.signers) == 1 && isPSS(tree.signers[0].SignatureAlgorithm) {
			return true
		}
	}
	return false
}

// tstInfo is RFC 3161's TSTInfo, as far as a report reads it.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	SerialNumber *big.Int
	Time         time.Time        `asn1:"generalized"`
	Accuracy     asn1.RawValue    `asn1:"optional"`
	Ordering     bool             `asn1:"optional,default:false"`
	Nonce        *big.Int         `asn1:"optional"`
	TSA          asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions   []pkix.Extension `asn1:"optional,tag:1"`
}

// readTSTInfo reads a token's TSTInfo, its encapsulated content, once its
// signature is checked.
func readTSTInfo(der []byte, tree signatureTree) (*timestamp.Timestamp, error) {
	var info tstInfo
	if _, err := asn1.Unmarshal(tree.content, &info); err != nil {
		return nil, fmt.Errorf("unreadable TSTInfo: %w", err)
	}
	hash, ok := digestFromOID(info.MessageImprint.HashAlgorithm.Algorithm)
	if !ok || len(info.MessageImprint.HashedMessage) == 0 {
		return nil, fmt.Errorf("the timestamp's imprint is unreadable")
	}
	return &timestamp.Timestamp{RawToken: der, HashAlgorithm: hash, HashedMessage: info.MessageImprint.HashedMessage,
		Time: info.Time, SerialNumber: info.SerialNumber, Policy: info.Policy, Ordering: info.Ordering, Nonce: info.Nonce,
		Certificates: tree.certificates, Extensions: info.Extensions}, nil
}
