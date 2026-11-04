package infrastructure

// Parsing the EU List of the Lists (LOTL).
//
// The LOTL is the root of trust for every national list: it publishes, for each
// territory, the address of its trusted list and the certificates its scheme
// operator signs with. That is exactly what turns a downloaded TSL from
// inventory into something verifiable, and it removes the hardcoded URL table:
// the addresses come from the source of truth instead of from a constant in a Go
// file that goes stale.
//
// Measured on 2026-11-03: 32 territories, 147 certificates, 472 KB.

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"codeberg.org/simplicer/firma-it/src/trust/domain"
)

// LOTLParser reads the EU list of trusted lists.
type LOTLParser struct{}

// pointer is one territory entry in the LOTL.
type lotlPointer struct {
	territory    string
	location     string
	mimeType     string
	certificates []*x509.Certificate
	tslType      string
}

// Parse returns the national lists the LOTL points at.
func (LOTLParser) Parse(reader io.Reader) (domain.LOTL, error) {
	decoder := xml.NewDecoder(bufio.NewReaderSize(reader, 64*1024))
	decoder.CharsetReader = charsetReader

	var (
		result     domain.LOTL
		current    lotlPointer
		inPointer  bool
		depth      int
		issued     string
		nextUpdate string
	)

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return domain.LOTL{}, fmt.Errorf("read LOTL XML: %w", err)
		}

		switch element := token.(type) {
		case xml.StartElement:
			depth++
			switch element.Name.Local {
			case "OtherTSLPointer":
				inPointer = true
				current = lotlPointer{}
			case "TSLLocation":
				if text, err := readText(decoder); err == nil {
					current.location = strings.TrimSpace(text)
				}
				depth--
			case "SchemeTerritory":
				if text, err := readText(decoder); err == nil {
					current.territory = strings.TrimSpace(text)
				}
				depth--
			case "MimeType":
				if text, err := readText(decoder); err == nil {
					current.mimeType = strings.TrimSpace(text)
				}
				depth--
			case "TSLType":
				if text, err := readText(decoder); err == nil {
					current.tslType = strings.TrimSpace(text)
				}
				depth--
			case "X509Certificate":
				if text, err := readText(decoder); err == nil {
					if certificate := parsePEMCertificate(text); certificate != nil {
						current.certificates = append(current.certificates, certificate)
					}
				}
				depth--
			case "IssueDateTime":
				if text, err := readText(decoder); err == nil && issued == "" {
					issued = strings.TrimSpace(text)
				}
				depth--
			case "NextUpdate":
				if text, err := readText(decoder); err == nil && nextUpdate == "" {
					nextUpdate = strings.TrimSpace(text)
				}
				depth--
			}
		case xml.EndElement:
			depth--
			if element.Name.Local == "OtherTSLPointer" && inPointer {
				inPointer = false

				// A pointer to another pointer (the EU list pointing at itself) is
				// not a national list.
				if current.territory == "" || current.location == "" || current.territory == "EU" {
					continue
				}

				result.Entries = append(result.Entries, domain.LOTLEntry{
					Territory:    current.territory,
					Location:     current.location,
					MimeType:     current.mimeType,
					Certificates: current.certificates,
				})
			}
		}
	}

	if len(result.Entries) == 0 {
		return domain.LOTL{}, fmt.Errorf("the LOTL carries no territory entries")
	}

	sort.Slice(result.Entries, func(left, right int) bool {
		return result.Entries[left].Territory < result.Entries[right].Territory
	})

	result.Issued, _ = parseTimestamp(issued)
	result.NextUpdate, _ = parseTimestamp(nextUpdate)
	return result, nil
}

// parsePEMCertificate decodes one base64 certificate, tolerating line breaks.
func parsePEMCertificate(text string) *x509.Certificate {
	var buffer bytes.Buffer
	for _, character := range text {
		switch character {
		case ' ', '\n', '\r', '\t':
			continue
		}
		buffer.WriteRune(character)
	}

	decoded, err := base64.StdEncoding.DecodeString(buffer.String())
	if err != nil {
		return nil
	}
	certificate, err := x509.ParseCertificate(decoded)
	if err != nil {
		return nil
	}
	return certificate
}

// parseTimestamp reads the date formats a LOTL may use.
func parseTimestamp(text string) (time.Time, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if value, parseErr := time.Parse(layout, trimmed); parseErr == nil {
			return value, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp %q", trimmed)
}
