package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"codeberg.org/simplicer/firma-it/src/entrypoint/serve"
	"codeberg.org/simplicer/firma-it/src/signing/application"
	"codeberg.org/simplicer/firma-it/src/signing/infrastructure"
	verificationapp "codeberg.org/simplicer/firma-it/src/verification/application"
	verificationinfra "codeberg.org/simplicer/firma-it/src/verification/infrastructure"
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
		fmt.Fprintln(stderr, "usage: firma-it serve [flags]")
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
		Version: Version,
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
	if explicit := os.Getenv("FIRMA_IT_TOKEN_DIR"); explicit != "" {
		return explicit, nil
	}
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); runtime != "" {
		return filepath.Join(runtime, "firma-it"), nil
	}

	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine where to keep the token: %w", err)
	}
	return filepath.Join(base, "firma-it"), nil
}
