// Package cli is the console adapter: it parses flags, builds the use case and
// renders the result. It contains no signing logic.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	"codeberg.org/simplicer/firma-it/src/signing/domain"
	"codeberg.org/simplicer/firma-it/src/signing/infrastructure"
)

// Exit codes. They are part of the contract with scripts and AI callers.
const (
	exitOK      = 0
	exitInvalid = 1
	exitUsage   = 2
)

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "trust":
		return runTrust(args[1:], stdout, stderr)
	case "timestamp", "tsa":
		return runTimestamp(args[1:], stdout, stderr)
	case "verify-tsr":
		return runVerifyTimestamp(args[1:], stdout, stderr)
	case "certificate", "cert":
		return runCertificate(args[1:], stdout, stderr)
	case "asic":
		return runAsic(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "handler":
		return runHandler(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, Version)
		return exitOK
	case "help", "--help", "-h":
		printUsage(stdout)
		return exitOK
	}

	fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
	printUsage(stderr)
	return exitUsage
}

// runSign implements `firma-it sign`.
func runSign(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		format     = flags.String("format", "pades", "signature format: cades | pades | xades")
		level      = flags.String("level", "bes", "signature level: bes | t | lt | lta")
		output     = flags.String("out", "", "output path (default: derived from the input)")
		p12Path    = flags.String("p12", "", "PKCS#12 file with the signing certificate")
		pemPath    = flags.String("pem", "", "PEM bundle with certificate and private key")
		passphrase = flags.String("pass", "", "passphrase for the P12 or PEM file")
		pin        = flags.String("pin", "", "PIN for PKCS#11 tokens")
		tokenLabel = flags.String("token", "", "PKCS#11 token label (smartcard)")
		module     = flags.String("module", defaultPKCS11Module, "PKCS#11 module path")
		name       = flags.String("name", "", "signer display name (default: certificate CN)")
		reason     = flags.String("reason", "", "reason for signing")
		location   = flags.String("location", "", "location of signing")
		tsaURL     = flags.String("tsa", "", "RFC 3161 timestamp authority URL")
		tsaUser    = flags.String("tsa-user", "", "TSA basic-auth username")
		tsaSecret  = flags.String("tsa-pass", "", "TSA basic-auth password")
		onlineRev  = flags.Bool("online-revocation", false,
			"query OCSP and embed the answers in /DSS (required for --level lt)")
		page       = flags.Int("page", 1, "page for the visible seal (1-based)")
		boxes      = boxList{}
		enveloping = flags.Bool("enveloping", false, "XAdES enveloping (default: enveloped)")
		asJSON     = flags.Bool("json", false, "machine-readable output")
	)

	// --box is repeatable: a signature can carry several marks (a rubric per
	// page plus a full stamp) and all of them share one cryptographic value.
	flags.Var(&boxes, "box", "seal box x1,y1,x2,y2 in PDF points (repeatable; PAGE:x1,y1,x2,y2 to pick the page)")

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: firma-it sign <document> [flags]")
		flags.PrintDefaults()
	}

	// Go's flag package stops at the first non-flag argument, but every CLI
	// convention (and every AI caller) writes `firma-it sign FILE --flag`.
	// The document is therefore extracted first and the flags are parsed from
	// what remains, keeping both orders working.
	documentPath, remaining, err := extractDocument(args)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		flags.Usage()
		return exitUsage
	}
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}

	document, err := domain.OpenDocument(documentPath)
	if err != nil {
		fmt.Fprintf(stderr, "invalid document: %v\n", err)
		return exitUsage
	}

	signatureFormat, err := domain.ParseFormat(*format)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	signatureLevel, err := domain.ParseLevel(*level)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	signer, err := buildSigner(signerOptions{
		name: *name, p12Path: *p12Path, pemPath: *pemPath, passphrase: *passphrase,
		pin: *pin, tokenLabel: *tokenLabel, module: *module,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	placements, err := buildPlacements(*page, boxes)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	timestamper := infrastructure.NewRfc3161Timestamper()
	useCase := application.NewSignDocument(
		infrastructure.DiskStore{},
		application.SystemClock{},
		infrastructure.CertificateInspector{},
		infrastructure.NewCadesSigner(timestamper),
		infrastructure.NewPadesSigner(timestamper),
		infrastructure.NewXadesSigner(timestamper),
	)

	artefact, err := useCase.Execute(context.Background(), application.Request{
		Document:        document,
		Format:          signatureFormat,
		Level:           signatureLevel,
		Signer:          signer,
		OutputPath:      *output,
		Placements:      placements,
		Reason:          *reason,
		Location:        *location,
		TimestampURL:    *tsaURL,
		TimestampUser:   *tsaUser,
		TimestampSecret: *tsaSecret,
		Enveloping:      *enveloping,
		EmbedRevocation: *onlineRev,
	})
	if err != nil {
		fmt.Fprintf(stderr, "signing failed: %v\n", err)
		return exitInvalid
	}

	if *asJSON {
		encodeJSON(stdout, artefact)
		return exitOK
	}

	printArtefact(stdout, artefact)
	return exitOK
}

// extractDocument pulls the single positional argument out of the argument
// list, wherever it appears, and returns the flags around it.
func extractDocument(args []string) (documentPath string, remaining []string, err error) {
	valueFlags := map[string]bool{
		"-format": true, "--format": true, "-level": true, "--level": true,
		"-lang": true, "--lang": true, "-territory": true, "--territory": true,
		"-out": true, "--out": true, "-p12": true, "--p12": true,
		"-pem": true, "--pem": true, "-pass": true, "--pass": true,
		"-pin": true, "--pin": true, "-token": true, "--token": true,
		"-module": true, "--module": true, "-name": true, "--name": true,
		"-reason": true, "--reason": true, "-location": true, "--location": true,
		"-tsa": true, "--tsa": true, "-tsa-user": true, "--tsa-user": true,
		"-tsa-pass": true, "--tsa-pass": true, "-page": true, "--page": true,
		"-box": true, "--box": true,
	}

	var positional []string
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if valueFlags[argument] && index+1 < len(args) {
			remaining = append(remaining, argument, args[index+1])
			index++
			continue
		}
		if len(argument) > 0 && argument[0] == '-' {
			remaining = append(remaining, argument)
			continue
		}
		positional = append(positional, argument)
	}

	switch len(positional) {
	case 0:
		return "", remaining, fmt.Errorf("sign needs a document path")
	case 1:
		return positional[0], remaining, nil
	default:
		return "", remaining, fmt.Errorf("sign takes one document, got %d: %v", len(positional), positional)
	}
}

// signerOptions groups the key-source flags.
type signerOptions struct {
	name       string
	p12Path    string
	pemPath    string
	passphrase string
	pin        string
	tokenLabel string
	module     string
}

// buildSigner resolves the key source from the flags, enforcing exactly one.
func buildSigner(options signerOptions) (domain.Signer, error) {
	sources := 0
	for _, value := range []string{options.p12Path, options.pemPath, options.tokenLabel} {
		if value != "" {
			sources++
		}
	}
	if sources == 0 {
		return domain.Signer{}, errors.New("no key source: use --p12, --pem or --token")
	}
	if sources > 1 {
		return domain.Signer{}, errors.New("ambiguous key source: use only one of --p12, --pem, --token")
	}

	displayName := options.name
	if displayName == "" {
		displayName = "signer"
	}

	if options.tokenLabel != "" {
		return domain.NewSigner(displayName, domain.FromToken,
			domain.WithToken(options.module, options.tokenLabel, options.pin))
	}

	path := options.p12Path
	source := domain.FromP12
	if path == "" {
		path = options.pemPath
		source = domain.FromPEM
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return domain.Signer{}, fmt.Errorf("read key material %s: %w", path, err)
	}

	return domain.NewSigner(displayName, source,
		domain.WithKeyMaterial(content),
		domain.WithPassphrase(options.passphrase))
}

// boxList collects repeated --box flags.
type boxList []string

// String implements flag.Value.
func (b *boxList) String() string { return strings.Join(*b, " ") }

// Set appends one box specification.
func (b *boxList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("empty --box")
	}
	*b = append(*b, value)
	return nil
}

// buildPlacements parses every --box into a placement.
//
// Accepted forms:
//
//	x1,y1,x2,y2            uses the --page value
//	PAGE:x1,y1,x2,y2       explicit page, so one command can stamp a rubric on
//	                       each page of a long document
//
// With no --box at all, a single default stamp is placed in the bottom-right
// corner of --page, which is what most signatures need.
func buildPlacements(page int, boxes boxList) ([]domain.SealPlacement, error) {
	if len(boxes) == 0 {
		return []domain.SealPlacement{domain.DefaultSeal(page)}, nil
	}

	placements := make([]domain.SealPlacement, 0, len(boxes))
	for _, raw := range boxes {
		targetPage := page
		specification := raw
		if colon := strings.Index(raw, ":"); colon > 0 {
			parsedPage, err := strconv.Atoi(strings.TrimSpace(raw[:colon]))
			if err != nil || parsedPage < 1 {
				return nil, fmt.Errorf("--box %q: the part before ':' must be a page number", raw)
			}
			targetPage = parsedPage
			specification = raw[colon+1:]
		}

		values, err := parseBoxValues(specification)
		if err != nil {
			return nil, fmt.Errorf("--box %q: %w", raw, err)
		}

		placement, err := domain.PlaceSeal(targetPage, values[0], values[1], values[2], values[3])
		if err != nil {
			return nil, fmt.Errorf("--box %q: %w", raw, err)
		}
		placements = append(placements, placement)
	}
	return placements, nil
}

// parseBoxValues reads the four coordinates.
func parseBoxValues(specification string) ([4]float64, error) {
	var values [4]float64

	parts := strings.Split(specification, ",")
	if len(parts) != 4 {
		return values, fmt.Errorf("needs four values: x1,y1,x2,y2")
	}
	for index, part := range parts {
		parsed, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
		if err != nil {
			return values, fmt.Errorf("value %q is not a number", part)
		}
		values[index] = parsed
	}
	return values, nil
}

// artefactJSON is the stable JSON shape consumed by agents and scripts.
type artefactJSON struct {
	Path       string `json:"path"`
	Format     string `json:"format"`
	Standard   string `json:"standard"`
	Level      string `json:"level"`
	Size       int    `json:"size_bytes"`
	SignedAt   string `json:"signed_at"`
	Signer     string `json:"signer"`
	HasSeal    bool   `json:"has_seal"`
	SealCount  int    `json:"seal_count"`
	SelfSigned bool   `json:"self_signed"`
}

func encodeJSON(writer io.Writer, artefact application.Artefact) {
	payload := artefactJSON{
		Path:       artefact.Path,
		Format:     string(artefact.Format),
		Standard:   artefact.Format.Standard(),
		Level:      string(artefact.Level),
		Size:       artefact.Size,
		SignedAt:   artefact.SignedAt.Format(time.RFC3339),
		Signer:     artefact.SignerName,
		HasSeal:    artefact.HasSeal,
		SealCount:  artefact.SealCount,
		SelfSigned: artefact.SelfSigned,
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)
}

func printArtefact(writer io.Writer, artefact application.Artefact) {
	fmt.Fprintf(writer, "signed  %s\n", artefact.Path)
	fmt.Fprintf(writer, "  format  %s (%s)\n", artefact.Format, artefact.Format.Standard())
	fmt.Fprintf(writer, "  level   %s\n", artefact.Level)
	fmt.Fprintf(writer, "  size    %d bytes\n", artefact.Size)
	if artefact.SealCount > 0 {
		fmt.Fprintf(writer, "  seals   %d visible\n", artefact.SealCount)
	}
	if artefact.SelfSigned {
		fmt.Fprintf(writer, "  warning self-signed certificate: valid cryptography, no third-party trust\n")
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprint(writer, `firma-it — AdES signatures without proprietary code

usage:
  firma-it sign <document> [flags]
  firma-it verify <document> [flags]
  firma-it trust  sync|list [flags]
  firma-it timestamp <file> --tsa <url>      (or --hash <hex>)
  firma-it verify-tsr <token.tsr> [file]
  firma-it certificate <file.p12|.pem|.crt>   (or: cert)
  firma-it asic <document> <signature>        (ASiC-S / ASiC-E container)
  firma-it serve --root <dir> --listen 127.0.0.1:0   (local HTTP API)

flags:
  --format   cades (.p7m) | pades (.pdf) | xades (.xml)   default: pades
  --level    bes | t | lt | lta                            default: bes
  --p12      PKCS#12 file (any authority, or self-signed)
  --pem      PEM bundle with certificate and private key
  --token    PKCS#11 token label (smartcard)
  --pass     passphrase for the P12 or PEM
  --pin      PIN for the token
  --tsa      RFC 3161 timestamp authority URL
  --reason   reason for signing
  --location location of signing
  --page     page for the visible seal                      default: 1
  --box      seal box x1,y1,x2,y2 in PDF points
  --json     machine-readable output
  --out      output path

examples:
  firma-it sign contratto.pdf --p12 mario.p12 --pass secret --reason Contratto
  firma-it sign fattura.xml --format cades --p12 mario.p12 --level t --tsa https://tsa.example/
  firma-it sign atto.pdf --token "Carta de Ejemplo" --pin 000000 --box 300,60,540,140
  firma-it sign doc.pdf --p12 self.p12 --json
`)
}

// Version is injected at build time via -ldflags.
var Version = "0.1.0-unstable"

// defaultPKCS11Module points at the OpenSC module on Linux.
var defaultPKCS11Module = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
