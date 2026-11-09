package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/localtls"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// runAfirma implements `trebaruna afirma <uri>`: answer an AutoFirma request
// from the command line. The request is shown in full on stderr; it is
// signed only with --approve and a key, otherwise the site hears CANCEL.
func runAfirma(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "local-tls" {
		return runLocalTLS(args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("afirma", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keys := addKeyFlags(flags, "sign with")
	var (
		approve     = flags.Bool("approve", false, "approve the request as shown (without it, the site hears CANCEL)")
		file        = flags.String("file", "", "the file to sign when the page sends no data")
		saveTo      = flags.String("save-to", "", "where save and signandsave write")
		interactive = flags.Bool("interactive", false,
			"JSON lines: the proposal on stdout, the decision (key, secrets) read from stdin; for the desktop window")
	)
	flagArguments, positional := splitArguments(args, valueFlagsWith("file", "save-to"))
	if err := flags.Parse(flagArguments); err != nil {
		return exitUsage
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "usage: trebaruna afirma '<afirma://…>' [--p12 key.p12 | --card | --firefox] [--approve]")
		return exitUsage
	}

	flagApprover := &commandLineApprover{approve: *approve, file: *file, saveTo: *saveTo, stderr: stderr}
	var approver application.Approver = flagApprover
	if *interactive {
		lines := &interactiveApprover{input: bufio.NewScanner(stdin), output: stdout}
		lines.input.Buffer(make([]byte, 64*1024), 1<<20)
		approver = lines
	}
	if *approve && !*interactive {
		key, err := buildSigner(keys.options(""))
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitUsage
		}
		flagApprover.key = key
	}

	invocation, err := domain.ParseInvocation(positional[0])
	if err != nil {
		if *interactive {
			encodeJSONLine(stdout, map[string]any{"type": "outcome", "error": err.Error()})
		}
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	courier := infrastructure.NewIntermediateServer()
	use := application.NewAnswerPage(approver, infrastructure.NewNativePageSigner(), infrastructure.KeyCertificates{},
		infrastructure.WebData{}, infrastructure.LocalFiles{}, courier, courier).
		WithBatches(infrastructure.NewBatchServices(), infrastructure.KeyRawSigner{})
	if invocation.Operation == domain.WebSocket {
		return serveLocalChannel(invocation, use, *interactive, stdout, stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	answer, err := use.Execute(ctx, invocation)
	if *interactive {
		outcome := map[string]any{"type": "outcome", "answer": answer.Text(), "delivered": err == nil}
		if err != nil {
			outcome["error"] = err.Error()
		}
		encodeJSONLine(stdout, outcome)
		if err != nil {
			return exitInvalid
		}
		return exitOK
	}
	fmt.Fprintln(stdout, answer.Text())
	printConnections(stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	return exitOK
}

// commandLineApprover shows the proposal and applies the flags' decision.
type commandLineApprover struct {
	approve bool
	key     signing.Signer
	file    string
	saveTo  string
	stderr  io.Writer
}

// Approve prints what the page asks and decides as the flags say.
func (a *commandLineApprover) Approve(_ context.Context, proposal application.Proposal) (application.Decision, error) {
	fmt.Fprintf(a.stderr, "afirma:// request\n  operation  %s\n  site       %s\n", proposal.Operation, proposal.Site)
	if proposal.AppName != "" {
		fmt.Fprintf(a.stderr, "  calls itself %s (its own claim)\n", proposal.AppName)
	}
	if proposal.Format != "" {
		fmt.Fprintf(a.stderr, "  format     %s\n", proposal.Format)
	}
	if proposal.Policy != "" {
		fmt.Fprintf(a.stderr, "  policy     %s (the signature will declare it)\n", proposal.Policy)
	}
	if len(proposal.Roles) > 0 {
		fmt.Fprintf(a.stderr, "  role       %s (the signature will claim it)\n", strings.Join(proposal.Roles, ", "))
	}
	if proposal.Place != "" {
		fmt.Fprintf(a.stderr, "  place      %s (the signature will declare it)\n", proposal.Place)
	}
	switch {
	case proposal.DataSize > 0:
		fmt.Fprintf(a.stderr, "  data       %d bytes, SHA-256 %s\n", proposal.DataSize, proposal.DataSHA256)
	case proposal.DataURL != "":
		fmt.Fprintf(a.stderr, "  data       to download from %s\n", proposal.DataURL)
	case proposal.ChooseFile:
		fmt.Fprintln(a.stderr, "  data       a file you choose (--file)")
	}
	for _, item := range proposal.Items {
		fmt.Fprintf(a.stderr, "  document   %s (%s, %s)\n", item.ID, item.Format, item.Suboperation)
	}
	for _, expression := range proposal.Filter.Expressions() {
		fmt.Fprintf(a.stderr, "  accepts    certificates matching %s\n", expression)
	}
	for _, warning := range proposal.Warnings {
		fmt.Fprintf(a.stderr, "  warning    %s\n", warning)
	}
	if proposal.PlaceSeal != "" {
		fmt.Fprintf(a.stderr, "  seal       the page asks for a visible seal (%s); the command line places none, so the signature is invisible\n", proposal.PlaceSeal)
	}
	if proposal.Remembered != "" {
		fmt.Fprintf(a.stderr, "  kept       %s's key, from the page's earlier request (the key given here is used)\n", proposal.Remembered)
	}
	if !a.approve {
		fmt.Fprintln(a.stderr, "  not approved: answering CANCEL (approve with --approve and a key)")
		return application.Decision{}, nil
	}
	decision := application.Decision{Approved: true, Key: a.key, SavePath: a.saveTo}
	if proposal.ChooseFile && a.file != "" {
		content, err := os.ReadFile(a.file)
		if err != nil {
			return application.Decision{}, err
		}
		decision.File, decision.FileName = content, filepath.Base(a.file)
	}
	return decision, nil
}

// interactiveApprover is the desktop's side of the protocol: one JSON line
// with the proposal, one JSON line back with the decision.
type interactiveApprover struct {
	input  *bufio.Scanner
	output io.Writer
}

// proposalLine is the proposal as the window reads it.
type proposalLine struct {
	Type          string     `json:"type"`
	Operation     string     `json:"operation"`
	Site          string     `json:"site"`
	AppName       string     `json:"app_name"`
	Format        string     `json:"format"`
	DataSize      int        `json:"data_size"`
	DataSHA256    string     `json:"data_sha256"`
	DataURL       string     `json:"data_url"`
	ChooseFile    bool       `json:"choose_file"`
	SuggestedName string     `json:"suggested_name"`
	Items         []itemLine `json:"items"`
	Filters       []string   `json:"filters"`
	Warnings      []string   `json:"warnings"`
	Rejected      string     `json:"rejected,omitempty"`
	Policy        string     `json:"policy,omitempty"`
	Roles         []string   `json:"roles,omitempty"`
	Place         string     `json:"place,omitempty"`
	// Remembered is the holder of the key kept from the page's earlier
	// request (sticky), which the window may approve with again.
	Remembered string `json:"remembered,omitempty"`
	// Seal is the page's visibleSignature (want, optional); SealDocument a
	// private copy of the PDF to place it on, removed once decided.
	Seal         string `json:"seal,omitempty"`
	SealDocument string `json:"seal_document,omitempty"`
}

// sealLine is where the window placed the seal, in PDF points.
type sealLine struct {
	Page        int     `json:"page"`
	LowerLeftX  float64 `json:"llx"`
	LowerLeftY  float64 `json:"lly"`
	UpperRightX float64 `json:"urx"`
	UpperRightY float64 `json:"ury"`
}

type itemLine struct {
	ID           string `json:"id"`
	Format       string `json:"format"`
	Suboperation string `json:"suboperation"`
}

// decisionLine is the window's answer; secrets travel here, through the
// pipe, never on a command line.
type decisionLine struct {
	Approved bool `json:"approved"`
	Key      struct {
		P12         string `json:"p12"`
		PEM         string `json:"pem"`
		Card        bool   `json:"card"`
		Token       string `json:"token"`
		Certificate string `json:"certificate"`
		Module      string `json:"module"`
		Firefox     bool   `json:"firefox"`
		NSSDB       string `json:"nss_db"`
	} `json:"key"`
	Passphrase string `json:"passphrase"`
	PIN        string `json:"pin"`
	File       string `json:"file"`
	SaveTo     string `json:"save_to"`
	// Remembered approves with the kept key instead of one named here.
	Remembered bool `json:"remembered"`
	// Seal is where the person placed the seal, when asked to.
	Seal *sealLine `json:"seal"`
}

// Approve writes the proposal and reads the decision.
func (a *interactiveApprover) Approve(_ context.Context, proposal application.Proposal) (application.Decision, error) {
	line := proposalLine{Type: "proposal", Operation: string(proposal.Operation), Site: proposal.Site, AppName: proposal.AppName,
		Format: proposal.Format, DataSize: proposal.DataSize, DataSHA256: proposal.DataSHA256, DataURL: proposal.DataURL,
		ChooseFile: proposal.ChooseFile, SuggestedName: proposal.SuggestedName, Filters: proposal.Filter.Expressions(),
		Warnings: proposal.Warnings, Rejected: proposal.Rejected, Items: []itemLine{},
		Policy: proposal.Policy, Roles: proposal.Roles, Place: proposal.Place, Remembered: proposal.Remembered,
		Seal: proposal.PlaceSeal}
	for _, item := range proposal.Items {
		line.Items = append(line.Items, itemLine{ID: item.ID, Format: item.Format, Suboperation: item.Suboperation})
	}
	if len(proposal.SealDocument) > 0 {
		path, remove, err := privateCopy(proposal.SealDocument)
		if err != nil {
			return application.Decision{}, err
		}
		defer remove()
		line.SealDocument = path
	}
	encodeJSONLine(a.output, line)

	if !a.input.Scan() || strings.TrimSpace(a.input.Text()) == "" {
		return application.Decision{}, nil // the window closed: not approved
	}
	var decision decisionLine
	if err := json.Unmarshal(a.input.Bytes(), &decision); err != nil {
		return application.Decision{}, fmt.Errorf("unreadable decision: %w", err)
	}
	if !decision.Approved {
		return application.Decision{}, nil
	}
	result := application.Decision{Approved: true, SavePath: decision.SaveTo, UseRemembered: decision.Remembered}
	if decision.Seal != nil {
		result.Seal = domain.SealBox{Page: decision.Seal.Page, LowerLeftX: decision.Seal.LowerLeftX, LowerLeftY: decision.Seal.LowerLeftY,
			UpperRightX: decision.Seal.UpperRightX, UpperRightY: decision.Seal.UpperRightY}
	}
	if decision.File != "" {
		content, err := os.ReadFile(decision.File)
		if err != nil {
			return application.Decision{}, err
		}
		result.File, result.FileName = content, filepath.Base(decision.File)
	}
	if decision.Remembered {
		return result, nil
	}
	key, err := buildSigner(signerOptions{
		p12Path: decision.Key.P12, pemPath: decision.Key.PEM, passphrase: decision.Passphrase, pin: decision.PIN,
		card: decision.Key.Card, tokenLabel: decision.Key.Token, certificate: decision.Key.Certificate,
		module: decision.Key.Module, store: storeOptions{firefox: decision.Key.Firefox, directory: decision.Key.NSSDB},
	})
	if err != nil {
		return application.Decision{}, err
	}
	result.Key = key
	return result, nil
}

// privateCopy writes the document the window places the seal on where only
// this user reads it; remove deletes it.
func privateCopy(content []byte) (string, func(), error) {
	directory, err := os.MkdirTemp("", "trebaruna-seal-")
	if err != nil {
		return "", nil, err
	}
	remove := func() { _ = os.RemoveAll(directory) }
	path := filepath.Join(directory, "document.pdf")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		remove()
		return "", nil, err
	}
	return path, remove, nil
}

// encodeJSONLine writes one JSON object on one line.
func encodeJSONLine(writer io.Writer, value any) {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

// serveLocalChannel serves a page's WebSocket channel (ADR-0019) until the
// page goes: each operation is approved as any other, and in interactive
// mode the window hears where the channel listens, each operation's
// outcome, and when the page has gone.
func serveLocalChannel(invocation domain.Invocation, use *application.AnswerPage, interactive bool, stdout, stderr io.Writer) int {
	report := func(line map[string]any) {
		if interactive {
			encodeJSONLine(stdout, line)
		}
	}
	channel, err := domain.ReadLocalChannel(invocation)
	if err != nil {
		report(map[string]any{"type": "outcome", "error": err.Error()})
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	directory, err := localtls.Directory()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	material, err := localtls.Load(directory)
	if err != nil {
		report(map[string]any{"type": "outcome", "error": err.Error(), "local_tls": "missing"})
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	answers := application.NewAnswerLocalChannel(use, channel)
	server := infrastructure.LocalServer{
		Certificate: material.Server,
		Listening: func(port int) {
			report(map[string]any{"type": "listening", "port": port})
			fmt.Fprintf(stderr, "listening on 127.0.0.1:%d\n", port)
		},
		Answer: func(ctx context.Context, message string) string {
			operationCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()
			answer := answers.Answer(operationCtx, message)
			// An operation's answer, or over 4.1 the result getresult fetched.
			if !strings.HasPrefix(message, "echo=") && answer != "#wait" {
				report(map[string]any{"type": "outcome", "answer": answer, "delivered": true, "session": true})
			}
			return answer
		},
	}
	if err := server.Serve(context.Background(), channel.Ports); err != nil {
		report(map[string]any{"type": "outcome", "error": err.Error()})
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	report(map[string]any{"type": "closed"})
	return exitOK
}
