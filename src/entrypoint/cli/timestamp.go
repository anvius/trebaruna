package cli

// Independent timestamping: `firma-it timestamp` and `firma-it verify-tsr`.
//
// Two kinds of timestamp: over a document's hash and
// over a bare hash. Both are useful without signing
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
	"strings"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/infrastructure"
	"github.com/digitorus/timestamp"
)

// runTimestamp implements `firma-it timestamp`.
func runTimestamp(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("timestamp", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		output  = flags.String("out", "", "where to write the .tsr (default: <file>.tsr)")
		tsaURL  = flags.String("tsa", "", "timestamp authority URL (required)")
		tsaUser = flags.String("tsa-user", "", "TSA basic-auth username")
		tsaPass = flags.String("tsa-pass", "", "TSA basic-auth password")
		hashHex = flags.String("hash", "", "timestamp this hex digest instead of a file")
		asJSON  = flags.Bool("json", false, "machine-readable output")
	)

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: firma-it timestamp <file> --tsa <url> [flags]")
		fmt.Fprintln(stderr, "       firma-it timestamp --hash <hex> --tsa <url> [flags]")
		flags.PrintDefaults()
	}

	// The file argument is optional when --hash is given, so the positional
	// extractor is bypassed in that case.
	var path string
	remaining := args
	if *hashHex == "" {
		var err error
		path, remaining, err = extractDocument(args)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			flags.Usage()
			return exitUsage
		}
	}
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}

	if *tsaURL == "" {
		fmt.Fprintln(stderr, "a timestamp authority is required: pass --tsa <url>")
		return exitUsage
	}

	// What gets timestamped: the digest of the file, or a digest the caller
	// already computed. The TSA never sees the document, only its hash.
	var digest []byte
	switch {
	case *hashHex != "":
		decoded, err := hex.DecodeString(strings.TrimSpace(*hashHex))
		if err != nil || len(decoded) == 0 {
			fmt.Fprintf(stderr, "--hash must be a hex digest: %v\n", err)
			return exitUsage
		}
		digest = decoded
	default:
		content, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "read %q: %v\n", path, err)
			return exitUsage
		}
		sum := sha256.Sum256(content)
		digest = sum[:]
	}

	timestamper := infrastructure.NewRfc3161Timestamper()
	response, err := timestamper.Token(
		contextWithTimeout(60*time.Second), digest, *tsaURL, *tsaUser, *tsaPass,
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
	if destination == "" {
		if path != "" {
			destination = path + ".tsr"
		} else {
			destination = "timestamp.tsr"
		}
	}
	if err := os.WriteFile(destination, response, 0o644); err != nil {
		fmt.Fprintf(stderr, "write %q: %v\n", destination, err)
		return exitInvalid
	}

	if *asJSON {
		encodeJSONValue(stdout, map[string]any{
			"path":       destination,
			"digest":     hex.EncodeToString(digest),
			"algorithm":  "sha256",
			"time":       token.Time.UTC().Format(time.RFC3339),
			"tsa":        firstCertificateName(token),
			"serial":     token.SerialNumber.String(),
			"policy":     token.Policy.String(),
			"size_bytes": len(response),
		})
		return exitOK
	}

	fmt.Fprintf(stdout, "timestamped %s\n", destination)
	fmt.Fprintf(stdout, "  time    %s\n", token.Time.UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "  tsa     %s\n", firstCertificateName(token))
	fmt.Fprintf(stdout, "  digest  %s\n", hex.EncodeToString(digest))
	return exitOK
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
		fmt.Fprintln(stderr, "usage: firma-it verify-tsr <token.tsr> [file] [--hash <hex>] [--json]")
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
