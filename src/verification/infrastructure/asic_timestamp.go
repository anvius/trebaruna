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
	report, parsed := v.cades.timeStampReport(raw, covered)
	report.Format = "RFC 3161"
	if parsed {
		// The manifest it covers must still describe the files.
		checkManifest(unpacked, references, &report)
	}
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
