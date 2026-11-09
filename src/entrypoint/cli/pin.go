package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// runPIN implements `trebaruna pin change|unlock|change-puk`.
//
// The secrets come only from the environment: TREBARUNA_PIN (current),
// TREBARUNA_PUK, TREBARUNA_NEW_PIN and TREBARUNA_NEW_PUK. The card is read
// before any attempt, so a locked card, a locked PUK or a new secret of the
// wrong length is refused without the card counting a try.
func runPIN(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "change" && args[0] != "unlock" && args[0] != "change-puk") {
		fmt.Fprintln(stderr, "usage: trebaruna pin change|unlock|change-puk [--token label] [--module path] [--json]")
		fmt.Fprintln(stderr, "  change:     $TREBARUNA_PIN (current) and $TREBARUNA_NEW_PIN")
		fmt.Fprintln(stderr, "  unlock:     $TREBARUNA_PUK and $TREBARUNA_NEW_PIN")
		fmt.Fprintln(stderr, "  change-puk: $TREBARUNA_PUK (current) and $TREBARUNA_NEW_PUK")
		return exitUsage
	}
	action := args[0]

	flags := flag.NewFlagSet("pin "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		label  = flags.String("token", "", "label of the card, when there are several")
		module = flags.String("module", "", "PKCS#11 module path (default: OpenSC, found on this system)")
		asJSON = flags.Bool("json", false, "machine-readable output")
	)
	if err := flags.Parse(args[1:]); err != nil {
		return exitUsage
	}

	path, err := moduleOrOpenSC(*module)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	card, err := domain.NewCard(path, *label)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	replacement := os.Getenv(newPINVariable)
	switch action {
	case "change":
		err = application.NewChangeCardPIN(infrastructure.CardPINChanger{}).
			Execute(context.Background(), card, os.Getenv(pinVariable), replacement)
	case "change-puk":
		err = application.NewChangeCardPUK(infrastructure.CardPUKChanger{}).
			Execute(context.Background(), card, os.Getenv(pukVariable), os.Getenv(newPUKVariable))
	default:
		err = application.NewUnlockCard(infrastructure.CardUnlocker{}).
			Execute(context.Background(), card, os.Getenv(pukVariable), replacement)
	}
	if err != nil {
		if *asJSON {
			encodeJSONValue(stdout, map[string]any{"changed": false, "error": err.Error()})
		}
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}

	if *asJSON {
		encodeJSONValue(stdout, map[string]any{"changed": true, "action": action})
		return exitOK
	}
	switch action {
	case "change":
		fmt.Fprintln(stdout, "PIN changed: the card now takes the new one")
	case "change-puk":
		fmt.Fprintln(stdout, "PUK changed: the card now takes the new one")
	default:
		fmt.Fprintln(stdout, "card unlocked: the new PIN is set")
	}
	return exitOK
}
