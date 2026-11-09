package cli

// Independent timestamping: `trebaruna timestamp` and `trebaruna verify-tsr`.
//
// Two timestamp operations are useful (a timestamp over a document hash, and
// TSR_TIMESTAMP (a timestamp over a bare hash). Both are useful without signing
// anything: proving a document existed at a moment is a separate legal act from
// signing it, and asking a client to sign in order to obtain that proof is a
// workaround, not a feature.
//
// The output is a .tsr file, the DER TimeStampResp, which any verifier accepts.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/asic"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/tsd"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
	"github.com/digitorus/timestamp"
)

// runTimestamp implements `trebaruna timestamp`.
func runTimestamp(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("timestamp", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		output  = flags.String("out", "", "where to write the .tsr (default: <file>.tsr)")
		tsaURL  = flags.String("tsa", "", "timestamp authority URL (required)")
		tsaUser = flags.String("tsa-user", "", "TSA basic-auth username")
		tsaPass = flags.String("tsa-pass", "", "TSA basic-auth password (or $TREBARUNA_TSA_PASS)")
		hashHex = flags.String("hash", "", "timestamp this hex digest instead of a file")
		asTSD   = flags.Bool("tsd", false, "write <file>.tsd: the document and its token together (RFC 5544)")
		asASiC  = flags.Bool("asic", false, "write <file>.asics: the document and META-INF/timestamp.tst (ASiC-S, EN 319 162-1)")
		asJSON  = flags.Bool("json", false, "machine-readable output")
	)

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna timestamp <file> --tsa <url> [--tsd | --asic] [flags]")
		fmt.Fprintln(stderr, "       trebaruna timestamp --hash <hex> --tsa <url> [flags]")
		flags.PrintDefaults()
	}

	// Flags may follow the positional argument, which Go's flag package does not
	// support on its own: split them first so `timestamp a.pdf --tsa url` works.
	flagArguments, positional := splitArguments(args, map[string]bool{
		"-out": true, "--out": true, "-tsa": true, "--tsa": true,
		"-tsa-user": true, "--tsa-user": true, "-tsa-pass": true, "--tsa-pass": true,
		"-hash": true, "--hash": true,
	})
	if err := flags.Parse(flagArguments); err != nil {
		return exitUsage
	}

	// The document is optional when a digest is supplied.
	path := ""
	if *hashHex == "" {
		if len(positional) != 1 {
			fmt.Fprintln(stderr, "timestamp needs exactly one document, or --hash <hex>")
			flags.Usage()
			return exitUsage
		}
		path = positional[0]
	}

	if *tsaURL == "" {
		fmt.Fprintln(stderr, "a timestamp authority is required: pass --tsa <url>")
		return exitUsage
	}

	if (*asTSD || *asASiC) && path == "" {
		fmt.Fprintln(stderr, "--tsd and --asic keep the document with its token, so they need the document, not --hash")
		return exitUsage
	}
	if *asTSD && *asASiC {
		fmt.Fprintln(stderr, "--tsd and --asic exclude each other: one container or the other")
		return exitUsage
	}

	// What gets timestamped: the digest of the file, or a digest the caller
	// already computed. The TSA never sees the document, only its hash.
	var digest []byte
	var content []byte
	switch {
	case *hashHex != "":
		decoded, err := hex.DecodeString(strings.TrimSpace(*hashHex))
		if err != nil || len(decoded) == 0 {
			fmt.Fprintf(stderr, "--hash must be a hex digest: %v\n", err)
			return exitUsage
		}
		digest = decoded
	default:
		read, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "read %q: %v\n", path, err)
			return exitUsage
		}
		content = read
		sum := sha256.Sum256(content)
		digest = sum[:]
	}

	timestamper := infrastructure.NewRfc3161Timestamper()
	response, err := timestamper.Token(
		contextWithTimeout(60*time.Second), digest, *tsaURL, *tsaUser, secretFrom(*tsaPass, tsaSecretVariable),
	)
	if err != nil {
		fmt.Fprintf(stderr, "timestamp failed: %v\n", err)
		return exitInvalid
	}

	token, err := timestamp.ParseResponse(response)
	if err != nil {
		fmt.Fprintf(stderr, "the TSA response is not a valid token: %v\n", err)
		return exitInvalid
	}

	destination := *output
	switch {
	case destination != "":
	case *asTSD:
		destination = path + ".tsd"
	case *asASiC:
		destination = path + ".asics"
	case path != "":
		destination = path + ".tsr"
	default:
		destination = "timestamp.tsr"
	}
	written := response
	switch {
	case *asTSD:
		if written, err = timeStampedData(content, path, response); err != nil {
			fmt.Fprintf(stderr, "build the .tsd: %v\n", err)
			return exitInvalid
		}
	case *asASiC:
		if written, err = timeStampedContainer(content, path, response); err != nil {
			fmt.Fprintf(stderr, "build the .asics: %v\n", err)
			return exitInvalid
		}
	}
	if err := os.WriteFile(destination, written, 0o644); err != nil {
		fmt.Fprintf(stderr, "write %q: %v\n", destination, err)
		return exitInvalid
	}

	standing := timestampStanding(token)
	if *asJSON {
		encodeJSONValue(stdout, map[string]any{
			"qualified":    standing.qualified,
			"qualified_by": standing.service,
			"standing":     standing.note,
			"path":         destination,
			"digest":       hex.EncodeToString(digest),
			"algorithm":    "sha256",
			"time":         token.Time.UTC().Format(time.RFC3339),
			"tsa":          firstCertificateName(token),
			"serial":       token.SerialNumber.String(),
			"policy":       token.Policy.String(),
			"size_bytes":   len(written),
			"network":      connections(),
		})
		return exitOK
	}

	fmt.Fprintf(stdout, "timestamped %s\n", destination)
	fmt.Fprintf(stdout, "  time    %s\n", token.Time.UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "  tsa     %s\n", firstCertificateName(token))
	fmt.Fprintf(stdout, "  digest  %s\n", hex.EncodeToString(digest))
	fmt.Fprintf(stdout, "  status  %s\n", standing.note)
	printConnections(stdout)
	return exitOK
}

// authorityStanding is whether a timestamp authority is qualified, by the
// cached list.
type authorityStanding struct {
	qualified bool
	service   string
	note      string
}

// timestampStanding judges the token's authority against the authenticated
// list of the territory already cached: offline, as every verdict is by default.
func timestampStanding(token *timestamp.Timestamp) authorityStanding {
	territory := defaultTerritory()
	list, err := verificationinfra.NewCachedTrustProvider().Load(territory)
	if err != nil || !list.Authenticated {
		return authorityStanding{note: fmt.Sprintf("qualification unknown: the %s trusted list is not cached (trebaruna trust sync)", territory)}
	}
	if len(token.Certificates) == 0 {
		return authorityStanding{note: "qualification unknown: the token carries no certificate"}
	}
	service, found := list.QualifiedTimestampService(token.Certificates[0])
	if !found {
		return authorityStanding{note: fmt.Sprintf("not a qualified timestamp: the %s trusted list grants no such service to this authority", territory)}
	}
	name := service.ProviderName + ": " + service.ServiceName
	return authorityStanding{qualified: true, service: name, note: "qualified timestamp (" + name + ")"}
}

// runVerifyTimestamp checks a .tsr against a file or a digest.
//
// Without this, a user holding a .tsr cannot tell whether it still corresponds
// to the document, which is the only question that matters.
func runVerifyTimestamp(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-tsr", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		hashHex = flags.String("hash", "", "hex digest to compare against")
		asJSON  = flags.Bool("json", false, "machine-readable output")
	)

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna verify-tsr <token.tsr> [file] [--hash <hex>] [--json]")
		fmt.Fprintln(stderr, "       trebaruna verify-tsr <document.tsd> [--json]")
		flags.PrintDefaults()
	}

	// Flags may appear after the positional arguments (`verify-tsr a.tsr b.pdf
	// --hash ...`), which Go's flag package does not support on its own. The
	// arguments are therefore split first: everything that is a known flag with
	// its value goes to Parse, the rest is positional.
	flagArguments, positional := splitArguments(args, map[string]bool{
		"-hash": true, "--hash": true,
	})

	if err := flags.Parse(flagArguments); err != nil {
		return exitUsage
	}

	if len(positional) == 0 {
		flags.Usage()
		return exitUsage
	}

	tokenPath := positional[0]
	content, err := os.ReadFile(tokenPath)
	if err != nil {
		fmt.Fprintf(stderr, "read %q: %v\n", tokenPath, err)
		return exitUsage
	}

	if tsd.Is(content) {
		return verifyTimeStampedData(tokenPath, content, *asJSON, stdout, stderr)
	}

	token, err := timestamp.ParseResponse(content)
	if err != nil {
		fmt.Fprintf(stderr, "not a timestamp token: %v\n", err)
		return exitInvalid
	}

	matches := true
	var note string
	switch {
	case *hashHex != "":
		decoded, decodeErr := hex.DecodeString(strings.TrimSpace(*hashHex))
		if decodeErr != nil {
			fmt.Fprintf(stderr, "--hash is not hex: %v\n", decodeErr)
			return exitUsage
		}
		matches = equalDigest(decoded, token.HashedMessage)
	case len(positional) > 1:
		document, readErr := os.ReadFile(positional[1])
		if readErr != nil {
			fmt.Fprintf(stderr, "read %q: %v\n", positional[1], readErr)
			return exitUsage
		}
		hasher := token.HashAlgorithm.New()
		hasher.Write(document)
		matches = equalDigest(hasher.Sum(nil), token.HashedMessage)
	default:
		note = "no document or digest supplied; only the token structure was checked"
	}

	if *asJSON {
		encodeJSONValue(stdout, map[string]any{
			"path":    tokenPath,
			"time":    token.Time.UTC().Format(time.RFC3339),
			"tsa":     firstCertificateName(token),
			"matches": matches,
			"note":    note,
		})
	} else {
		fmt.Fprintf(stdout, "%s\n", tokenPath)
		fmt.Fprintf(stdout, "  time    %s\n", token.Time.UTC().Format(time.RFC3339))
		fmt.Fprintf(stdout, "  tsa     %s\n", firstCertificateName(token))
		if note != "" {
			fmt.Fprintf(stdout, "  note    %s\n", note)
		}
		if matches {
			fmt.Fprintln(stdout, "  imprint matches")
		} else {
			fmt.Fprintln(stdout, "  imprint DOES NOT match")
		}
	}

	// Exit codes: no comparison must never look like a pass. Scripted callers
	// rely on the code, so "structure only" reports untrusted (3).
	if note != "" {
		return exitUnverified
	}
	if !matches {
		return exitTampered
	}
	return exitOK
}

// splitArguments separates flag/value pairs from positional arguments.
//
// It knows which flags take a value; anything else that starts with "-" is
// treated as a boolean flag. This is the smallest thing that behaves like a
// normal CLI without pulling in a parser library.
func splitArguments(args []string, valueFlags map[string]bool) (flags []string, positional []string) {
	for index := 0; index < len(args); index++ {
		argument := args[index]

		if valueFlags[argument] && index+1 < len(args) {
			flags = append(flags, argument, args[index+1])
			index++
			continue
		}
		if strings.HasPrefix(argument, "-") && argument != "-" {
			flags = append(flags, argument)
			continue
		}
		positional = append(positional, argument)
	}
	return flags, positional
}

// firstCertificateName returns the TSA common name, or a placeholder.
func firstCertificateName(token *timestamp.Timestamp) string {
	if len(token.Certificates) == 0 {
		return "unknown"
	}
	return token.Certificates[0].Subject.CommonName
}

// equalDigest compares two digests in constant time.
func equalDigest(left, right []byte) bool {
	return subtle.ConstantTimeCompare(left, right) == 1
}

// contextWithTimeout is a small helper so the call site stays readable.
func contextWithTimeout(d time.Duration) (ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	_ = cancel // the process exits after the command; leaking one timer is fine
	return ctx
}

// encodeJSONValue writes any value as indented JSON.
func encodeJSONValue(writer io.Writer, value any) {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

// timeStampedContainer is an ASiC-S time-stamped container (ETSI EN 319
// 162-1, 4.3): the document and, in META-INF/timestamp.tst, the token over
// it (the TimeStampToken, not the authority's whole response).
func timeStampedContainer(content []byte, path string, response []byte) ([]byte, error) {
	token, err := cms.ExtractToken(response)
	if err != nil {
		return nil, err
	}
	return asic.Write(domain.ASiCS.MediaType(), []asic.Entry{
		{Name: filepath.Base(path), Content: content},
		{Name: "META-INF/timestamp.tst", Content: token},
	})
}
