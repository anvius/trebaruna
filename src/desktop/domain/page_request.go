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
}

// Validate refuses an approval that misses something the proposal needs,
// before anything reaches the command.
func (d PageDecision) Validate(proposal PageProposal) error {
	if !d.Approved {
		return nil
	}
	if proposal.NeedsKey() {
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
}
