package infrastructure

import (
	"encoding/asn1"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// oidArchiveTimeStampV3 is archive-time-stamp-v3 (ETSI EN 319 122-1,
// id-aa-ets-archiveTimestampV3). 1.2.840.113549.1.9.16.2.48, which
// trebaruna wrote before 0.67.1, is the v2 of TS 101 733.
var oidArchiveTimeStampV3 = cms.OIDArchiveTimeStampV3

// describeArchiveTimeStamps checks each archive-time-stamp-v3 of the
// SignerInfo at index (CAdES-A, EN 319 122-1 5.5.3): the token verifies,
// every element its hash index lists is still in the signature, and its
// imprint is the digest of what it seals. The signer and the verifier share
// the computation (cms.ArchiveTimeStampV3Input).
func describeArchiveTimeStamps(envelope []byte, index int, unsigned asn1.RawValue, content []byte, report *domain.SignerReport) {
	for _, tokenDER := range attributeValues(unsigned, oidArchiveTimeStampV3) {
		token, err := parseTimeStamp(tokenDER)
		if err != nil {
			report.Findings = append(report.Findings, domain.Finding{
				Code: "timestamp.invalid", Status: domain.StatusBad,
				Message: "the archive timestamp cannot be parsed or does not verify", Detail: err.Error(),
			})
			continue
		}
		sealed, err := cms.TokenHashIndex(tokenDER)
		var prefix, current []byte
		if err == nil {
			prefix, current, err = cms.ArchiveTimeStampV3Input(envelope, index, content, token.HashAlgorithm)
		}
		if err == nil {
			err = cms.HashIndexHolds(sealed, current)
		}
		if err == nil {
			err = imprintOf(token, append(prefix, sealed...))
		}
		if err != nil {
			report.Findings = append(report.Findings, domain.Finding{
				Code: "timestamp.archive_unbound", Status: domain.StatusWarn,
				Message: "the archive timestamp does not cover this signature as EN 319 122-1 reads: it proves nothing about it",
				Detail:  err.Error(),
			})
			continue
		}
		report.Findings = append(report.Findings, domain.Finding{
			Code: "timestamp.archival", Status: domain.StatusGood,
			Message: "the signature carries an archive timestamp (CAdES-A) that covers it",
			Detail:  token.Time.UTC().Format(time.RFC3339),
		})
	}
}
