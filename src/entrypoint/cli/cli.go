// Package cli is the console adapter: it parses flags, builds the use case and
// renders the result. It contains no signing logic.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"

	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// Exit codes. They are part of the contract with scripts and AI callers.
const (
	exitOK      = 0
	exitInvalid = 1
	exitUsage   = 2
)

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunIO(args, os.Stdin, stdout, stderr)
}

// RunIO is Run with the standard input given: the interactive afirma
// protocol reads the person's decision from it.
func RunIO(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if !askedForJSON(args) {
		return dispatch(args, stdin, stdout, stderr)
	}
	// With --json, a failure is JSON too: what the command said on stderr,
	// on stdout, when it wrote nothing there itself (verify writes its
	// report whatever the verdict).
	var said bytes.Buffer
	written := &countingWriter{writer: stdout}
	code := dispatch(args, stdin, written, io.MultiWriter(stderr, &said))
	if code != exitOK && written.count == 0 {
		// The usage a command prints after a wrong flag is for a person.
		message, _, _ := strings.Cut(said.String(), "usage:")
		encodeJSONValue(stdout, map[string]any{"error": strings.TrimSpace(message), "exit_code": code})
	}
	return code
}

// askedForJSON reports --json among the arguments.
func askedForJSON(args []string) bool {
	for _, argument := range args {
		if argument == "--json" || argument == "-json" || argument == "--json=true" || argument == "-json=true" {
			return true
		}
	}
	return false
}

// countingWriter counts the bytes written through it.
type countingWriter struct {
	writer io.Writer
	count  int
}

func (w *countingWriter) Write(data []byte) (int, error) {
	written, err := w.writer.Write(data)
	w.count += written
	return written, err
}

func dispatch(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Each command reports the connections it made, not those of an earlier
	// command run in the same process (tests, the local server).
	transparency.Reset()
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
	case "token":
		return runToken(args[1:], stdout, stderr)
	case "pin":
		return runPIN(args[1:], stdout, stderr)
	case "encrypt":
		return runEncrypt(args[1:], stdout, stderr)
	case "recipients":
		return runRecipients(args[1:], stdout, stderr)
	case "afirma":
		return runAfirma(args[1:], stdin, stdout, stderr)
	case "decrypt":
		return runDecrypt(args[1:], stdout, stderr)
	case "asic":
		return runAsic(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "handler":
		return runHandler(args[1:], stdout, stderr)
	case "requests":
		return runRequests(args[1:], stdout, stderr)
	case "decide":
		return runDecide(args[1:], stdout, stderr)
	case "about":
		return runAbout(args[1:], stdout, stderr)
	case "extract":
		return runExtract(args[1:], stdout, stderr)
	case "fields":
		return runFields(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return exitOK
	case "help", "--help", "-h":
		printUsage(stdout)
		return exitOK
	}

	fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
	printUsage(stderr)
	return exitUsage
}

// runSign implements `trebaruna sign`.
func runSign(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		format    = flags.String("format", "", "signature format: cades | pades | xades | xmldsig | odf | ooxml (default: from the suffix)")
		level     = flags.String("level", "bes", "signature level: bes | t | lt | lta")
		output    = flags.String("out", "", "output path (default: derived from the input)")
		force     = flags.Bool("force", false, "replace an existing file at the output (never the document itself)")
		keys      = addKeyFlags(flags, "sign with")
		name      = flags.String("name", "", "signer display name (default: the holder printed on the certificate)")
		reason    = flags.String("reason", "", "reason for signing")
		location  = flags.String("location", "", "location of signing")
		tsaURL    = flags.String("tsa", "", "RFC 3161 timestamp authority URL")
		tsaUser   = flags.String("tsa-user", "", "TSA basic-auth username")
		tsaSecret = flags.String("tsa-pass", "", "TSA basic-auth password (or $TREBARUNA_TSA_PASS)")
		onlineRev = flags.Bool("online-revocation", false,
			"query OCSP and embed the answers in /DSS (required for --level lt)")
		page       = flags.Int("page", 1, "page for the visible seal (1-based)")
		boxes      = boxList{}
		enveloping = flags.Bool("enveloping", false, "XAdES enveloping (default: enveloped)")
		asicType   = flags.String("asic", "", "pack documents and their detached signature: s (one document, <document>.asics) or e (all the documents under one signature, <first>.asice)")
		invisible  = flags.Bool("invisible", false, "PAdES without any visible seal (excludes --box)")
		field      = flags.String("field", "", "sign in the PDF's empty signature field of this name, the seal in its box (excludes --box)")
		rubricPath = flags.String("rubric", "", "PNG or JPEG of a handwritten signature, drawn in the seal beside the certificate data")
		detached   = flags.Bool("detached", false, "the signature beside the document, which stays untouched: <document>.p7s (CAdES) or <document>.xsig (XAdES)")
		cosign     = flags.Bool("cosign", false, "add a parallel signature to the .p7m, .p7s or ASiC container given as document")
		counter    = flags.String("countersign", "", "counter-sign the signatures of the envelope, signed XML or ASiC container: leaves | all")
		signedDoc  = flags.String("content", "", "the document a detached .p7s signs, to co-sign it")
		policyName = flags.String("policy", "", "signature policy (EPES): age | age18 | facturae | facturae30")
		policyID   = flags.String("policy-id", "", "a policy by its parts: identifier (OID or URL)")
		policyHash = flags.String("policy-hash", "", "the policy document's digest, Base64")
		policyAlg  = flags.String("policy-hash-alg", "SHA1", "the digest algorithm of --policy-hash")
		policyURI  = flags.String("policy-qualifier", "", "the policy document's URL")
		role       = flags.String("role", "", "role the signer claims in XAdES (FacturaE: emisor, receptor, tercero)")
		asJSON     = flags.Bool("json", false, "machine-readable output")
	)

	// --box is repeatable: a signature can carry several marks (a rubric per
	// page plus a full stamp) and all of them share one cryptographic value.
	flags.Var(&boxes, "box", "seal box x1,y1,x2,y2 in PDF points (repeatable; PAGE:x1,y1,x2,y2 to pick the page)")

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna sign <document> [flags]")
		flags.PrintDefaults()
	}

	// Go's flag package stops at the first non-flag argument, but every CLI
	// convention (and every AI caller) writes `trebaruna sign FILE --flag`.
	// The document is therefore extracted first and the flags are parsed from
	// what remains, keeping both orders working.
	documents, remaining := splitSignArguments(args)
	if len(documents) == 0 {
		fmt.Fprintln(stderr, "sign needs at least one document")
		flags.Usage()
		return exitUsage
	}
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}
	container, err := domain.ParseContainer(*asicType)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if len(documents) > 1 && *output != "" && container != domain.ASiCE {
		fmt.Fprintln(stderr, "--out names one file; it cannot be used when signing several documents")
		return exitUsage
	}

	signatureLevel, err := domain.ParseLevel(*level)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	signer, err := buildSigner(keys.options(*name))
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	if *invisible && len(boxes) > 0 {
		fmt.Fprintln(stderr, "--invisible and --box exclude each other: an invisible signature has no seal")
		return exitUsage
	}
	var rubric domain.Rubric
	if *rubricPath != "" {
		if rubric, err = readRubric(*rubricPath); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitUsage
		}
	}
	if *field != "" && len(boxes) > 0 {
		fmt.Fprintln(stderr, "--field and --box exclude each other: the field already says where the seal goes")
		return exitUsage
	}
	var placements []domain.SealPlacement
	if !*invisible && *field == "" {
		if placements, err = buildPlacements(*page, boxes); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitUsage
		}
	}

	useCase := Signing(infrastructure.NewRfc3161Timestamper())

	// Every document gets the same settings; each format is still inferred from
	// its own suffix unless --format names one. One failure does not stop the
	// others: a batch reports what happened to each document.
	signOne := func(documentPath string, morePaths ...string) (application.Artefact, error) {
		document, err := domain.OpenDocument(documentPath)
		if err != nil {
			return application.Artefact{}, fmt.Errorf("invalid document: %w", err)
		}
		var more []domain.Document
		for _, path := range morePaths {
			other, err := domain.OpenDocument(path)
			if err != nil {
				return application.Artefact{}, fmt.Errorf("invalid document: %w", err)
			}
			more = append(more, other)
		}
		signatureFormat := document.InferFormat()
		if *format != "" {
			if signatureFormat, err = domain.ParseFormat(*format); err != nil {
				return application.Artefact{}, err
			}
		}
		policy, err := policyFor(*policyName, *policyID, *policyAlg, *policyHash, *policyURI, signatureFormat)
		if err != nil {
			return application.Artefact{}, err
		}
		var claimedRoles []string
		if *role != "" {
			claimedRoles = []string{*role}
		}
		artefact, err := useCase.Execute(context.Background(), application.Request{
			Policy:          policy,
			ClaimedRoles:    claimedRoles,
			Document:        document,
			Format:          signatureFormat,
			Level:           signatureLevel,
			Signer:          signer,
			OutputPath:      *output,
			Overwrite:       *force,
			Placements:      placements,
			Invisible:       *invisible,
			Field:           *field,
			PDFPassword:     os.Getenv(pdfPasswordVariable),
			Rubric:          rubric,
			Detached:        *detached,
			Cosign:          *cosign,
			Countersign:     *counter,
			ContentPath:     *signedDoc,
			Reason:          *reason,
			Location:        *location,
			TimestampURL:    *tsaURL,
			TimestampUser:   *tsaUser,
			TimestampSecret: secretFrom(*tsaSecret, tsaSecretVariable),
			Enveloping:      *enveloping,
			Container:       container,
			MoreDocuments:   more,
			EmbedRevocation: *onlineRev,
		})
		if err != nil {
			return application.Artefact{}, fmt.Errorf("signing failed: %w", passphraseHint(err))
		}
		return artefact, nil
	}

	// An ASiC-E container holds every document under one signature.
	if len(documents) == 1 || container == domain.ASiCE {
		artefact, err := signOne(documents[0], documents[1:]...)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitInvalid
		}
		if *asJSON {
			encodeJSON(stdout, artefact)
			return exitOK
		}
		printArtefact(stdout, artefact)
		return exitOK
	}
	return signBatch(documents, func(path string) (application.Artefact, error) { return signOne(path) }, *asJSON, stdout, stderr)
}

// passphraseHint adds where the passphrase goes when none was given.
func passphraseHint(err error) error {
	if strings.Contains(err.Error(), "does not open without its passphrase") {
		return fmt.Errorf("%w; give it in $%s", err, passphraseVariable)
	}
	return err
}

// extractDocument pulls the single positional argument out of the argument
// list, wherever it appears, and returns the flags around it; command names
// the command in the errors.
func extractDocument(command string, args []string) (documentPath string, remaining []string, err error) {
	positional, remaining := splitSignArguments(args)
	switch len(positional) {
	case 0:
		return "", remaining, fmt.Errorf("%s needs a document path", command)
	case 1:
		return positional[0], remaining, nil
	default:
		return "", remaining, fmt.Errorf("%s takes one document, got %d: %v", command, len(positional), positional)
	}
}

// signValueFlags are the sign flags that take a value, so the documents can
// be told apart from flag values wherever the flags appear.
var signValueFlags = valueFlagsWith("format", "level", "lang", "territory", "out", "name",
	"reason", "location", "tsa", "tsa-user", "tsa-pass", "page", "box", "content", "countersign",
	"policy", "policy-id", "policy-hash", "policy-hash-alg", "policy-qualifier", "role", "asic", "report", "rubric", "field")

// splitSignArguments separates the documents from the flags of `sign`.
func splitSignArguments(args []string) (positional, remaining []string) {
	remaining, positional = splitArguments(args, signValueFlags)
	return positional, remaining
}

// signerOptions groups the key-source flags.
type signerOptions struct {
	name        string
	p12Path     string
	pemPath     string
	passphrase  string
	pin         string
	card        bool
	tokenLabel  string
	certificate string
	module      string
	store       storeOptions
	// remote and credential name a CSC service and its credential;
	// oauthClient and oauthRedirect, its OAuth2 sign-in.
	remote        string
	credential    string
	oauthClient   string
	oauthRedirect string
}

// remoteService is the CSC service the flags name, with the secrets the
// environment carries (ADR-0006).
func (options signerOptions) remoteService() domain.RemoteService {
	return domain.RemoteService{
		Address: options.remote, Credential: options.credential,
		Token: os.Getenv("TREBARUNA_CSC_TOKEN"), User: os.Getenv("TREBARUNA_CSC_USER"), Password: os.Getenv("TREBARUNA_CSC_PASSWORD"),
		PIN: secretFrom(options.pin, pinVariable), OTP: os.Getenv("TREBARUNA_OTP"),
		OAuthClient: options.oauthClient, OAuthSecret: os.Getenv("TREBARUNA_CSC_CLIENT_SECRET"), OAuthRedirect: options.oauthRedirect,
	}
}

// buildSigner resolves the key source from the flags, enforcing exactly one.
func buildSigner(options signerOptions) (domain.Signer, error) {
	// Any card flag says the key is on a card; --card alone lets everything be found.
	card := options.card || options.tokenLabel != "" || options.certificate != "" || options.module != "" ||
		options.store.chosen()
	sources := 0
	remote := options.remote != ""
	for _, chosen := range []bool{options.p12Path != "", options.pemPath != "", card, remote} {
		if chosen {
			sources++
		}
	}
	if sources == 0 {
		return domain.Signer{}, errors.New("no key source: use --p12, --pem, --card (with --token / --certificate to choose), or --csc")
	}
	if sources > 1 {
		return domain.Signer{}, errors.New("ambiguous key source: use only one of --p12, --pem, a card (--card, --token, --certificate, --module), or --csc")
	}

	displayName := options.name
	if displayName == "" {
		displayName = domain.NameFromCertificate
	}

	if remote {
		return domain.NewSigner(displayName, domain.FromRemote, domain.WithRemoteService(options.remoteService()))
	}

	if card {
		module, parameters, err := cardModule(options.module, options.store)
		if err != nil {
			return domain.Signer{}, err
		}
		return domain.NewSigner(displayName, domain.FromToken,
			domain.WithToken(module, options.tokenLabel, secretFrom(options.pin, pinVariable)),
			domain.WithModuleParameters(parameters),
			domain.WithCertificateChoice(domain.ChooseCertificateBy(options.certificate)))
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
		domain.WithPassphrase(secretFrom(options.passphrase, passphraseVariable)))
}

// readRubric reads the image of --rubric.
func readRubric(path string) (domain.Rubric, error) {
	file, err := os.Open(path)
	if err != nil {
		return domain.Rubric{}, fmt.Errorf("--rubric: %w", err)
	}
	defer file.Close()
	rubric, err := domain.ReadRubric(file)
	if err != nil {
		return domain.Rubric{}, fmt.Errorf("--rubric %s: %w", path, err)
	}
	return rubric, nil
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
	// KeySource says where the key was (p12, pem, token, csc);
	// RemoteService names the provider of a remote key (ADR-0014).
	KeySource     string `json:"key_source"`
	RemoteService string `json:"remote_service,omitempty"`
	// DocumentSHA256 and SignedSHA256 let a person compare what was signed.
	DocumentSHA256 string `json:"document_sha256"`
	SignedSHA256   string `json:"signed_sha256"`
	// Network lists every connection the signature needed (ADR-0010).
	Network []transparencydomain.Connection `json:"network"`
}

func encodeJSON(writer io.Writer, artefact application.Artefact) {
	payload := receiptOf(artefact)
	payload.Network = connections()
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
	fmt.Fprintf(writer, "  signed  sha256 %s\n", artefact.DocumentDigest)
	fmt.Fprintf(writer, "  output  sha256 %s\n", artefact.SignedDigest)
	if artefact.SealCount > 0 {
		fmt.Fprintf(writer, "  seals   %d visible\n", artefact.SealCount)
	}
	if artefact.KeySource == domain.FromRemote {
		fmt.Fprintf(writer, "  key     remote, kept by %s (CSC): the hash left this computer, the key did not come to it\n", artefact.RemoteService)
	}
	if artefact.SelfSigned {
		fmt.Fprintf(writer, "  warning self-signed certificate: valid cryptography, no third-party trust\n")
	}
	printConnections(writer)
}

func printUsage(writer io.Writer) {
	fmt.Fprint(writer, `trebaruna — AdES signatures without proprietary code

usage:
  trebaruna sign <document> [flags]
  trebaruna verify <document> [flags]
  trebaruna trust  sync|list [flags]
  trebaruna timestamp <file> --tsa <url>      (or --hash <hex>)
  trebaruna verify-tsr <token.tsr> [file]
  trebaruna certificate <file.p12|.pem|.crt>   (or: cert)
  trebaruna token [--module <pkcs11.so>]     (list cards and their certificates)
  trebaruna pin change|unlock [--token L]    (new PIN; secrets only in $TREBARUNA_PIN/_PUK/_NEW_PIN)
  trebaruna asic <document> <signature>        (ASiC-S / ASiC-E container)
  trebaruna serve --root <dir> --listen 127.0.0.1:0   (local HTTP API)
  trebaruna extract <document.p7m> [--out path]  (the document inside one or more envelopes)
  trebaruna fields <document.pdf> [--json]      (a form's empty signature fields, for sign --field)
  trebaruna encrypt <file> --to <cert> [--to …]   (a .p7e only the recipients open)
  trebaruna recipients list|add <cert>|remove <who>   (the address book: --to saved:<who>)
  trebaruna decrypt <file.p7e> --p12|--card|…     (open a .p7e with your key)
  trebaruna afirma '<afirma://…>' [--approve]    (answer an AutoFirma request; shown first)
  trebaruna about [--json]                      (build, revision, dependencies and licences)

flags:
  --format   cades | pades | xades | xmldsig | odf | ooxml       default: from the suffix
  --level    bes | t | lt | lta                                  default: bes
  --p12      PKCS#12 file (any authority, or self-signed)
  --pem      PEM bundle with certificate and private key
  --card     the card in the reader: card and signing certificate found
  --token    PKCS#11 token label (smartcard)
  --certificate  certificate of the card: serial or fingerprint  default: the signing one
  --module   PKCS#11 module                                      default: OpenSC
  --firefox  a certificate of the Firefox store, used in place
  --nss-db   a certificate of this NSS store directory
  --policy   signature policy: age | age18 | facturae | facturae30
  --role     role claimed in XAdES (FacturaE: emisor by default)
  --pass     passphrase for the P12 or PEM
  --pin      PIN for the token (better: $TREBARUNA_PIN, kept off the command line)
  --tsa      RFC 3161 timestamp authority URL
  --reason   reason for signing
  --location location of signing
  --page     page for the visible seal                           default: 1
  --box      seal box x1,y1,x2,y2 in PDF points
  --rubric   PNG or JPEG of a handwritten signature, beside the data in the seal
  --json     machine-readable output
  --out      output path

examples:
  read -rs TREBARUNA_PASSPHRASE && export TREBARUNA_PASSPHRASE
  trebaruna sign contratto.pdf --p12 mario.p12 --reason Contratto
  trebaruna sign fattura.xml --format cades --p12 mario.p12 --level t --tsa https://tsa.example/
  trebaruna sign atto.pdf --token "Carta de Ejemplo" --box 300,60,540,140
  trebaruna sign atto.pdf --p12 mario.p12 --rubric firma.png
  trebaruna sign atto.pdf --card
  trebaruna sign atto.pdf --certificate 3f2a91c0 --format cades
  trebaruna sign doc.pdf --p12 self.p12 --json
`)
}

// version is the effective version string, resolved once.
//
// The Makefile injects the real value with -ldflags, which covers every binary
// this repository ships. A binary installed with `go install pkg@version` is
// built by the user's own toolchain, which applies no project flags — so when
// nothing was injected, the version the user asked for is read from the build
// information the toolchain records. Only when even that is absent, which
// happens in tests, does the fallback stand.
var version = resolveVersion()

// injectedVersion is set by -ldflags. The empty string is the sentinel: a
// linker injection of "" and no injection at all are the same thing.
var injectedVersion = ""

// resolveVersion reports the version this binary should claim.
func resolveVersion() string {
	if injectedVersion != "" {
		return injectedVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "0.0.0-dev"
}

// cardModule returns the PKCS#11 module and its parameters: NSS's for a
// software store, the one given, or OpenSC.
func cardModule(module string, store storeOptions) (string, string, error) {
	if !store.chosen() {
		found, err := moduleOrOpenSC(module)
		return found, "", err
	}
	if module != "" {
		return "", "", errors.New("--module names a card driver; a store (--firefox, --nss-db) uses NSS's own")
	}
	resolved, nss, err := store.resolve()
	if err != nil {
		return "", "", err
	}
	return nss, resolved.Parameters(), nil
}

// policyFor reads the policy flags: a known name, or the parts.
func policyFor(name, identifier, algorithm, hash, qualifier string, format domain.Format) (domain.SignaturePolicy, error) {
	switch {
	case name != "" && identifier != "":
		return domain.SignaturePolicy{}, errors.New("use --policy or --policy-id, not both")
	case name != "":
		return domain.NamedPolicy(name, format)
	case identifier != "":
		return domain.NewSignaturePolicy(identifier, algorithm, hash, qualifier)
	}
	return domain.SignaturePolicy{}, nil
}

// moduleOrOpenSC returns the PKCS#11 module given, or the OpenSC module
// installed on this system when none was.
func moduleOrOpenSC(module string) (string, error) {
	if module != "" {
		return module, nil
	}
	if found := infrastructure.OpenSCModule(); found != "" {
		return found, nil
	}
	return "", errors.New("OpenSC was not found on this system: install it (https://github.com/OpenSC/OpenSC) " +
		"or give the card's PKCS#11 module with --module <path>")
}
