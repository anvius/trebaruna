package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/serve"
	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationapp "codeberg.org/simplicer/trebaruna/src/verification/application"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// runServe starts the local HTTP API.
//
// It blocks until interrupted, which is what a server is expected to do, and it
// prints the token path rather than the token: a secret in the terminal ends up
// in shell history and in screenshots.
func runServe(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		address = flags.String("listen", "127.0.0.1:0", "loopback address to bind (port 0 picks a free one)")
		root    = flags.String("root", "", "directory a client may read from (repeatable)")

		roots []string
	)

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna serve [flags]")
		flags.PrintDefaults()
	}

	// -root is repeatable, so it is collected before parsing the rest.
	var remaining []string
	for index := 0; index < len(args); index++ {
		if args[index] == "-root" || args[index] == "--root" {
			if index+1 < len(args) {
				roots = append(roots, args[index+1])
				index++
			}
			continue
		}
		remaining = append(remaining, args[index])
	}

	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}
	if *root != "" {
		roots = append(roots, *root)
	}
	if len(roots) == 0 {
		// Defaulting to the working directory keeps the common case usable while
		// still refusing arbitrary paths: the server never reads outside what the
		// operator listed.
		workingDirectory, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "cannot determine the working directory: %v\n", err)
			return exitUsage
		}
		roots = append(roots, workingDirectory)
	}

	token, err := serve.NewToken()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	tokenDirectory, err := tokenLocation()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	tokenPath, err := serve.WriteToken(tokenDirectory, token)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	defer func() { _ = os.Remove(tokenPath) }()

	timestamper := infrastructure.NewRfc3161Timestamper()
	service := &serve.Service{
		Signer: application.NewSignDocument(
			infrastructure.DiskStore{},
			application.SystemClock{},
			infrastructure.CertificateInspector{},
			infrastructure.NewCadesSigner(timestamper),
			infrastructure.NewPadesSigner(timestamper),
			infrastructure.NewXadesSigner(timestamper),
		),
		Verifier: verificationapp.NewVerifyDocument(
			verificationinfra.NewPDFVerifier(),
			verificationinfra.NewCadesVerifier(),
			verificationinfra.NewCachedTrustProvider(),
			systemClock{},
		).WithXades(verificationinfra.NewXadesVerifier()),
		Files:   serve.RootedFiles{Roots: roots},
		Token:   token,
		Version: version,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bound, err := service.Listen(ctx, *address)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	fmt.Fprintf(stdout, "listening on http://%s\n", bound)
	fmt.Fprintf(stdout, "token       %s (0600, removed on exit)\n", tokenPath)
	fmt.Fprintf(stdout, "roots       %v\n", roots)
	fmt.Fprintf(stdout, "send it as  X-Firma-Token: $(cat %s)\n", tokenPath)
	fmt.Fprintln(stdout, "stop with   Ctrl-C")

	<-ctx.Done()
	return exitOK
}

// tokenLocation returns the directory the local token lives in.
//
// It follows the XDG runtime directory when available, which is per-user and
// usually tmpfs, so the secret never touches persistent storage.
func tokenLocation() (string, error) {
	if explicit := os.Getenv("TREBARUNA_TOKEN_DIR"); explicit != "" {
		return explicit, nil
	}
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); runtime != "" {
		return filepath.Join(runtime, "trebaruna"), nil
	}

	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine where to keep the token: %w", err)
	}
	return filepath.Join(base, "trebaruna"), nil
}

// runHandler receives a trebaruna:// URI from the operating system.
//
// It starts the local API in the background, registers the request, and waits for
// the window to decide. It prints nothing about the document beyond what the user
// needs: the URI comes from a web page, and echoing its contents back to a
// terminal the page cannot read is not a risk, but leaking the approval secret
// through a log would be.
func runHandler(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("handler", flag.ContinueOnError)
	flags.SetOutput(stderr)

	// The URI arrives as the first positional argument, and flag.Parse stops at
	// the first non-flag, so the URI and the flags are separated before parsing.
	var (
		root       string
		uri        string
		positional []string
		p12Path    string
		pemPath    string
		passphrase string
	)
	for index := 0; index < len(args); index++ {
		next := func() string {
			if index+1 < len(args) {
				index++
				return args[index]
			}
			return ""
		}
		switch args[index] {
		case "-root", "--root":
			root = next()
		case "-p12", "--p12":
			p12Path = next()
		case "-pem", "--pem":
			pemPath = next()
		case "-pass", "--pass":
			passphrase = next()
		default:
			positional = append(positional, args[index])
		}
	}
	if len(positional) == 0 {
		fmt.Fprintln(stderr, "usage: trebaruna handler trebaruna://sign?... [--root <dir>]")
		return exitUsage
	}
	uri = positional[0]

	screen, parameters, err := serve.ParseHandlerURI(uri)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	roots := []string{}
	if root != "" {
		roots = append(roots, root)
	}
	if len(roots) == 0 {
		workingDirectory, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "cannot determine the working directory: %v\n", err)
			return exitUsage
		}
		roots = append(roots, workingDirectory)
	}

	token, err := serve.NewToken()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	tokenDirectory, err := tokenLocation()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	tokenPath, err := serve.WriteToken(tokenDirectory, token)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	defer func() { _ = os.Remove(tokenPath) }()

	timestamper := infrastructure.NewRfc3161Timestamper()
	service := &serve.Service{
		Signer: application.NewSignDocument(
			infrastructure.DiskStore{},
			application.SystemClock{},
			infrastructure.CertificateInspector{},
			infrastructure.NewCadesSigner(timestamper),
			infrastructure.NewPadesSigner(timestamper),
			infrastructure.NewXadesSigner(timestamper),
		),
		Verifier: verificationapp.NewVerifyDocument(
			verificationinfra.NewPDFVerifier(),
			verificationinfra.NewCadesVerifier(),
			verificationinfra.NewCachedTrustProvider(),
			systemClock{},
		).WithXades(verificationinfra.NewXadesVerifier()),
		Files:   serve.RootedFiles{Roots: roots},
		Token:   token,
		Version: version,
	}

	keySource, err := buildSigner(signerOptions{
		name: "handler", p12Path: p12Path, pemPath: pemPath, passphrase: passphrase,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	address, err := service.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	// One path creates a pending signature for both callers. It is called
	// directly rather than over HTTP because the secret must stay in this
	// process: the API deliberately never returns it.
	pending, err := service.RegisterRequest(serve.RequestBody{
		Document:  parameters["document"],
		Format:    parameters["format"],
		Territory: parameters["territory"],
		Origin:    screen.Origin,
		Callback:  screen.Callback,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	_ = address

	// The secret is printed to the terminal and nowhere else: it is what the
	// desktop window needs to approve, and what a page cannot obtain.
	fmt.Fprintf(stdout, "request  %s\n", pending.ID)
	fmt.Fprintf(stdout, "verdict  %s\n", pending.Report.Verdict())
	fmt.Fprintf(stdout, "secret   %s\n", pending.Secret)
	fmt.Fprintf(stdout, "the desktop app must now approve this request; so does:\n")
	fmt.Fprintf(stdout, "  curl -X POST http://%s/v1/requests/%s/decision \\\n", address, pending.ID)
	fmt.Fprintf(stdout, "       -H 'X-Firma-Token: %s' \\\n", tokenPath)
	fmt.Fprintf(stdout, "       -d '{\"secret\":\"%s\",\"approved\":true}'\n", pending.Secret)
	fmt.Fprintln(stdout, "the request expires in 30 seconds")

	// The person at the machine decides here. Reading the answer from the terminal
	// is what makes this usable without a window: the request is printed, the
	// verdict is printed, and the answer is typed.
	fmt.Fprintf(stdout, "\nsign %s ?  [y/N] ", pending.Path)
	answer := ""
	if _, err := fmt.Fscan(os.Stdin, &answer); err != nil {
		fmt.Fprintf(stderr, "\nno answer read: %v\n", err)
		return exitUsage
	}

	approved := strings.EqualFold(strings.TrimSpace(answer), "y") ||
		strings.EqualFold(strings.TrimSpace(answer), "yes")

	if err := service.Pending.Decide(pending.ID, pending.Secret, approved); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	if !approved {
		fmt.Fprintln(stdout, "rejected; nothing was signed")
		return exitOK
	}

	delivery, err := service.Fulfil(ctx, pending.ID, keySource)
	if err != nil {
		fmt.Fprintf(stderr, "signing failed: %v\n", err)
		return exitInvalid
	}

	fmt.Fprintf(stdout, "signed   %s\n", delivery.ArtefactPath())
	if delivery.Callback != "" {
		if delivery.Delivered {
			fmt.Fprintf(stdout, "delivered to %s\n", delivery.Callback)
		} else {
			fmt.Fprintf(stdout, "NOT delivered: %s\n", delivery.Error)
			return exitInvalid
		}
	}
	return exitOK
}
