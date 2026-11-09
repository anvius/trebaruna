package infrastructure

// No build tag: plain os/exec, tested by `make test` with a stand-in command.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// CommandLinePageRequests answers afirma:// requests by driving
// `trebaruna afirma <uri> --interactive`: the command fetches the request and
// keeps the page waiting, prints each proposal as a JSON line, and reads each
// decision — key and secrets included — as a JSON line on its standard input,
// never on its command line.
type CommandLinePageRequests struct {
	BinaryPath string
}

// Open starts the command for the URI.
func (r CommandLinePageRequests) Open(ctx context.Context, uri string) (application.PageSession, error) {
	command := exec.CommandContext(ctx, r.BinaryPath, "afirma", uri, "--interactive")
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	lines := bufio.NewScanner(output)
	lines.Buffer(make([]byte, 64*1024), 4<<20)
	return &commandSession{command: command, input: input, lines: lines, stderr: &stderr}, nil
}

// commandSession is one running command.
type commandSession struct {
	command *exec.Cmd
	input   io.WriteCloser
	lines   *bufio.Scanner
	stderr  *strings.Builder
}

// stepLine is what the command prints.
type stepLine struct {
	Type          string   `json:"type"`
	Operation     string   `json:"operation"`
	Site          string   `json:"site"`
	AppName       string   `json:"app_name"`
	Format        string   `json:"format"`
	DataSize      int      `json:"data_size"`
	DataSHA256    string   `json:"data_sha256"`
	DataURL       string   `json:"data_url"`
	ChooseFile    bool     `json:"choose_file"`
	SuggestedName string   `json:"suggested_name"`
	Filters       []string `json:"filters"`
	Warnings      []string `json:"warnings"`
	Rejected      string   `json:"rejected"`
	Items         []struct {
		ID           string `json:"id"`
		Format       string `json:"format"`
		Suboperation string `json:"suboperation"`
	} `json:"items"`
	Answer    string `json:"answer"`
	Delivered bool   `json:"delivered"`
	Error     string `json:"error"`
}

// Next reads the next proposal or the outcome.
func (s *commandSession) Next() (domain.PageStep, error) {
	if !s.lines.Scan() {
		return domain.PageStep{}, errors.New(meaningfulLine(s.stderr.String(), "", errors.New("the command ended without an answer")))
	}
	var line stepLine
	if err := json.Unmarshal(s.lines.Bytes(), &line); err != nil {
		return domain.PageStep{}, fmt.Errorf("the command printed an unreadable line: %w", err)
	}
	if line.Type == "outcome" {
		return domain.PageStep{Outcome: &domain.PageOutcome{Answer: line.Answer, Delivered: line.Delivered, Error: line.Error}}, nil
	}
	proposal := domain.PageProposal{Operation: line.Operation, Site: line.Site, AppName: line.AppName, Format: line.Format,
		DataSize: line.DataSize, DataSHA256: line.DataSHA256, DataURL: line.DataURL, ChooseFile: line.ChooseFile,
		SuggestedName: line.SuggestedName, Filters: line.Filters, Warnings: line.Warnings, Rejected: line.Rejected}
	for _, item := range line.Items {
		proposal.Items = append(proposal.Items, domain.PageItem{ID: item.ID, Format: item.Format, Suboperation: item.Suboperation})
	}
	return domain.PageStep{Proposal: &proposal}, nil
}

// Decide writes the decision line.
func (s *commandSession) Decide(decision domain.PageDecision) error {
	line := map[string]any{"approved": decision.Approved}
	if decision.Approved {
		key := map[string]any{}
		switch {
		case decision.Card.Chosen() && decision.Card.Store == domain.StoreFirefox:
			key["firefox"], key["certificate"] = true, decision.Card.Fingerprint
		case decision.Card.Chosen():
			key["card"], key["token"], key["certificate"] = true, decision.Card.Token, decision.Card.Fingerprint
		case strings.HasSuffix(strings.ToLower(decision.KeyFile.Path), ".pem"):
			key["pem"] = decision.KeyFile.Path
		case decision.KeyFile.Path != "":
			key["p12"] = decision.KeyFile.Path
		}
		line["key"], line["passphrase"], line["pin"] = key, decision.KeyFile.Passphrase, decision.Card.PIN
		line["file"], line["save_to"] = decision.Document, decision.SaveTo
	}
	encoded, err := json.Marshal(line)
	if err != nil {
		return err
	}
	_, err = s.input.Write(append(encoded, '\n'))
	return err
}

// Close ends the command.
func (s *commandSession) Close() error {
	_ = s.input.Close()
	return s.command.Wait()
}

// compile-time check.
var _ application.PageRequests = CommandLinePageRequests{}
