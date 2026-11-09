package domain

import "strings"

// PageProposal is what a web page asks, as the window shows it before anything
// happens: who asks, for what, over which data, and what the protocol cannot
// protect.
type PageProposal struct {
	Operation     string
	Site          string
	AppName       string
	Format        string
	DataSize      int
	DataSHA256    string
	DataURL       string
	ChooseFile    bool
	SuggestedName string
	Items         []PageItem
	Filters       []string
	Warnings      []string
	// Rejected says why the certificate chosen last was refused.
	Rejected string
	// Policy, Roles and Place are what the signature will declare.
	Policy string
	Roles  []string
	Place  string
	// Remembered is the holder of the certificate kept from the page's
	// earlier request (sticky), which may be used again without choosing.
	Remembered string
	// Seal is the page's visibleSignature, "want" or "optional": the person
	// places the seal on SealDocument, a copy of the PDF the page sent, or
	// on the document they choose.
	Seal         string
	SealDocument string
}

// PageItem is one document of a batch.
type PageItem struct {
	ID           string
	Format       string
	Suboperation string
}

// Saves reports operations that write a file the person places.
func (p PageProposal) Saves() bool { return p.Operation == "save" || p.Operation == "signandsave" }

// NeedsKey reports operations that use a certificate.
func (p PageProposal) NeedsKey() bool { return p.Operation != "save" }

// PageDecision is the person's answer to a proposal.
type PageDecision struct {
	Approved bool
	// Card is the certificate of a card or of the Firefox store; when not
	// chosen, KeyFile is used.
	Card    CardKey
	KeyFile CertificateFile
	// Document is the file to sign when the page sent none.
	Document string
	// SaveTo is where save and signandsave write.
	SaveTo string
	// Remembered approves with the certificate kept from the page's
	// earlier request, instead of Card or KeyFile.
	Remembered bool
	// Seal is where the person placed the seal, when the page asked.
	Seal SealChoice
}

// Validate refuses an approval that misses something the proposal needs,
// before anything reaches the command.
func (d PageDecision) Validate(proposal PageProposal) error {
	if !d.Approved {
		return nil
	}
	if proposal.NeedsKey() && !(d.Remembered && proposal.Remembered != "") {
		switch {
		case d.Card.Chosen():
			if err := d.Card.problem(); err != nil {
				return err
			}
		case strings.TrimSpace(d.KeyFile.Path) == "":
			return Problem{Code: ProblemMissingKey}
		}
	}
	if proposal.ChooseFile && strings.TrimSpace(d.Document) == "" {
		return Problem{Code: ProblemMissingDocument}
	}
	if proposal.Saves() && strings.TrimSpace(d.SaveTo) == "" {
		return Problem{Code: ProblemMissingSaveTo}
	}
	return nil
}

// PageOutcome is how the request ended.
type PageOutcome struct {
	Answer    string
	Delivered bool
	Error     string
	// Session marks the outcome of one operation of a local channel, which
	// stays open for the page's next request.
	Session bool
	// MissingLocalTLS means the page asked for the local channel and the
	// certificate it needs is not installed (ADR-0019).
	MissingLocalTLS bool
}

// Declined reports a request the person refused.
func (o PageOutcome) Declined() bool { return o.Answer == "CANCEL" }

// Succeeded reports an answer the page received without an error.
func (o PageOutcome) Succeeded() bool {
	return o.Error == "" && o.Answer != "" && !o.Declined() && !strings.HasPrefix(o.Answer, "SAF_")
}

// PageStep is what comes next from the command: a proposal to decide, or the
// outcome.
type PageStep struct {
	Proposal *PageProposal
	Outcome  *PageOutcome
	// Listening is the port a local channel waits for the page on.
	Listening int
	// Closed means the page left the local channel.
	Closed bool
}
