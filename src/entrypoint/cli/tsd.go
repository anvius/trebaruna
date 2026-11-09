package cli

import (
	"fmt"
	"io"
	"mime"
	"path/filepath"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/tsd"
	"github.com/digitorus/timestamp"
)

// timeStampedData wraps the document and the token of a TimeStampResp in a
// .tsd, naming the file in its metadata.
func timeStampedData(content []byte, path string, response []byte) ([]byte, error) {
	token, err := tsd.TokenOf(response)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	return tsd.Encode(content, name, mime.TypeByExtension(filepath.Ext(name)), token)
}

// tsdToken is one checked token of a .tsd.
type tsdToken struct {
	Time    string `json:"time"`
	TSA     string `json:"tsa"`
	Matches bool   `json:"matches"`
	Renews  bool   `json:"renews"`
	Error   string `json:"error,omitempty"`
}

// verifyTimeStampedData checks every token of a .tsd: its signature, and that
// it covers what it must — the document for the first, the previous token for
// a renewal.
func verifyTimeStampedData(path string, content []byte, asJSON bool, stdout, stderr io.Writer) int {
	document, err := tsd.Decode(content)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	if len(document.Content) == 0 {
		fmt.Fprintf(stderr, "%s points at %q instead of carrying the document; check its token with the document\n",
			path, document.DataURI)
		return exitUnverified
	}

	intact := true
	tokens := make([]tsdToken, 0, len(document.Tokens))
	for index, raw := range document.Tokens {
		checked := tsdToken{Renews: index > 0}
		parsed, err := timestamp.Parse(raw)
		if err != nil {
			checked.Error = err.Error()
			intact = false
			tokens = append(tokens, checked)
			continue
		}
		hasher := parsed.HashAlgorithm.New()
		hasher.Write(document.Covered(index))
		checked.Matches = equalDigest(hasher.Sum(nil), parsed.HashedMessage)
		checked.Time = parsed.Time.UTC().Format(time.RFC3339)
		checked.TSA = firstCertificateName(parsed)
		intact = intact && checked.Matches
		tokens = append(tokens, checked)
	}

	if asJSON {
		encodeJSONValue(stdout, map[string]any{
			"path": path, "file_name": document.FileName, "media_type": document.MediaType,
			"size": len(document.Content), "matches": intact, "tokens": tokens,
		})
	} else {
		fmt.Fprintf(stdout, "%s\n", path)
		if document.FileName != "" {
			fmt.Fprintf(stdout, "  document  %s (%d bytes)\n", document.FileName, len(document.Content))
		}
		for _, token := range tokens {
			kind := "timestamp"
			if token.Renews {
				kind = "renewal  "
			}
			switch {
			case token.Error != "":
				fmt.Fprintf(stdout, "  %s unreadable: %s\n", kind, token.Error)
			case token.Matches:
				fmt.Fprintf(stdout, "  %s %s by %s: imprint matches\n", kind, token.Time, token.TSA)
			default:
				fmt.Fprintf(stdout, "  %s %s by %s: imprint DOES NOT match\n", kind, token.Time, token.TSA)
			}
		}
	}
	if !intact {
		return exitTampered
	}
	return exitOK
}
