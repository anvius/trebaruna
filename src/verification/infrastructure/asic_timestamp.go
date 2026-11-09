package infrastructure

import (
	"fmt"
	"os"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// timeStamp judges an ASiC time-stamp token (ETSI EN 319 162-1, 4.3 and
// 4.4): META-INF/timestamp.tst over the one document of an ASiC-S, or over
// the ASiCManifest that names it in an ASiC-E. It proves that what it
// covers existed at its time, not who signed it: the report names the
// timestamp authority, whose certificate is checked like a signer's.
func (v *AsicVerifier) timeStamp(unpacked container, entry string) ([]domain.SignerReport, []string, error) {
	covered, references, names, err := timeStampCoverage(unpacked, entry)
	if err != nil {
		return nil, nil, err
	}
	raw, err := os.ReadFile(unpacked.file(entry))
	if err != nil {
		return nil, nil, err
	}
	report := domain.SignerReport{Format: "RFC 3161"}
	token, err := parseTimeStamp(raw)
	if err != nil {
		report.Integrity = domain.StatusBad
		report.Findings = append(report.Findings, domain.Finding{Code: "timestamp.invalid", Status: domain.StatusBad,
			Message: "the timestamp cannot be parsed or does not verify", Detail: err.Error()})
		report.Trust = trustFromReport(report)
		return []domain.SignerReport{report}, names, nil
	}
	report.SignedAt, report.Timestamped = token.Time, true
	if len(token.Certificates) > 0 {
		describeCertificate(token.Certificates[0], &report)
		v.cades.describeIssuer(token.Certificates[0], token.Certificates, token.Time, &report)
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
	// The manifest it covers must still describe the files.
	checkManifest(unpacked, references, &report)
	report.Trust = trustFromReport(report)
	return []domain.SignerReport{report}, names, nil
}

// timeStampCoverage is what a time-stamp token covers: the ASiCManifest
// naming it (ASiC-E), with the references whose digests must match the
// files, or the one document of an ASiC-S; and the files that means.
func timeStampCoverage(unpacked container, entry string) ([]byte, []manifestReference, []string, error) {
	manifest, references, err := manifestFor(unpacked, entry)
	if err != nil {
		return nil, nil, nil, err
	}
	switch {
	case manifest != "":
		content, err := os.ReadFile(unpacked.file(manifest))
		names := make([]string, 0, len(references))
		for _, reference := range references {
			names = append(names, reference.name)
		}
		return content, references, names, err
	case !unpacked.extended && len(unpacked.documents) == 1:
		content, err := os.ReadFile(unpacked.file(unpacked.documents[0]))
		return content, nil, unpacked.documents, err
	}
	return nil, nil, nil, fmt.Errorf("nothing says what %s covers", entry)
}
