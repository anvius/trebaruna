package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
)

// batchResult is one document of a batch: its receipt or why it failed.
type batchResult struct {
	Document string        `json:"document"`
	Receipt  *artefactJSON `json:"receipt,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// batchJSON is the result of signing several documents in one run.
type batchJSON struct {
	Signed  int                             `json:"signed"`
	Failed  int                             `json:"failed"`
	Results []batchResult                   `json:"results"`
	Network []transparencydomain.Connection `json:"network"`
}

// signBatch signs every document, reports each one, and exits non-zero when
// any failed, so a script can tell a partial batch from a complete one.
func signBatch(documents []string, signOne func(string) (application.Artefact, error), asJSON bool, stdout, stderr io.Writer) int {
	report := batchJSON{}
	var stopped error
	for _, document := range documents {
		if stopped != nil {
			// The card refused the PIN on an earlier document. Trying it again
			// would spend another of the few attempts before the card locks.
			report.Failed++
			report.Results = append(report.Results, batchResult{Document: document, Error: notTried(stopped)})
			if !asJSON {
				fmt.Fprintf(stderr, "%s: %s\n", document, notTried(stopped))
			}
			continue
		}
		artefact, err := signOne(document)
		if err != nil {
			report.Failed++
			report.Results = append(report.Results, batchResult{Document: document, Error: err.Error()})
			if !asJSON {
				fmt.Fprintf(stderr, "%s: %v\n", document, err)
			}
			if domain.StopsCard(err) {
				stopped = err
			}
			continue
		}
		report.Signed++
		receipt := receiptOf(artefact)
		report.Results = append(report.Results, batchResult{Document: document, Receipt: &receipt})
		if !asJSON {
			fmt.Fprintf(stdout, "signed  %s → %s\n", document, artefact.Path)
		}
	}
	report.Network = connections()

	if asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		_ = encoder.Encode(report)
	} else {
		fmt.Fprintf(stdout, "\n%d signed, %d failed\n", report.Signed, report.Failed)
		printConnections(stdout)
	}
	if report.Failed > 0 {
		return exitInvalid
	}
	return exitOK
}

// notTried explains a document left unsigned after the card refused the PIN.
func notTried(cause error) string {
	return "not tried, so no other PIN attempt was spent: " + cause.Error()
}

// receiptOf is the JSON receipt of one signature, shared with single runs.
func receiptOf(artefact application.Artefact) artefactJSON {
	return artefactJSON{
		Path:           artefact.Path,
		Format:         string(artefact.Format),
		Standard:       artefact.Format.Standard(),
		Level:          string(artefact.Level),
		Size:           artefact.Size,
		SignedAt:       artefact.SignedAt.Format(time.RFC3339),
		Signer:         artefact.SignerName,
		HasSeal:        artefact.HasSeal,
		SealCount:      artefact.SealCount,
		SelfSigned:     artefact.SelfSigned,
		KeySource:      string(artefact.KeySource),
		RemoteService:  artefact.RemoteService,
		DocumentSHA256: artefact.DocumentDigest,
		SignedSHA256:   artefact.SignedDigest,
	}
}
