package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// runAfirma implements `trebaruna afirma <uri>`: answer an AutoFirma request
// from the command line. The request is shown in full on stderr; it is
// signed only with --approve and a key, otherwise the site hears CANCEL.
func runAfirma(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("afirma", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keys := addKeyFlags(flags, "sign with")
	var (
		approve = flags.Bool("approve", false, "approve the request as shown (without it, the site hears CANCEL)")
		file    = flags.String("file", "", "the file to sign when the page sends no data")
		saveTo  = flags.String("save-to", "", "where save and signandsave write")
	)
	flagArguments, positional := splitArguments(args, valueFlagsWith("file", "save-to"))
	if err := flags.Parse(flagArguments); err != nil {
		return exitUsage
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "usage: trebaruna afirma '<afirma://…>' [--p12 key.p12 | --card | --firefox] [--approve]")
		return exitUsage
	}

	approver := &commandLineApprover{approve: *approve, file: *file, saveTo: *saveTo, stderr: stderr}
	if *approve {
		key, err := buildSigner(keys.options(""))
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitUsage
		}
		approver.key = key
	}

	invocation, err := domain.ParseInvocation(positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	courier := infrastructure.NewIntermediateServer()
	use := application.NewAnswerPage(approver, infrastructure.NewNativePageSigner(), infrastructure.KeyCertificates{},
		infrastructure.WebData{}, infrastructure.LocalFiles{}, courier, courier).
		WithBatches(infrastructure.NewBatchServices(), infrastructure.KeyRawSigner{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	answer, err := use.Execute(ctx, invocation)
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
