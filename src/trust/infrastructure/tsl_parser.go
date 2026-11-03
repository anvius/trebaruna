// Package infrastructure reads official trust lists.
//
// The EU member states publish TSLs in ETSI TS 119 612 XML. The Italian list is
// about 3 MB with 56 providers and thousands of certificates, so it is parsed as
// a stream: loading it into a DOM would triple the memory for no benefit.
package infrastructure

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"codeberg.org/simplicer/firma-it/src/trust/domain"
)

// TSLParser reads an ETSI TS 119 612 trust list.
type TSLParser struct{}

// Parse reads the list and returns every service it publishes.
func (TSLParser) Parse(reader io.Reader) (domain.TrustList, error) {
	list := domain.TrustList{}

	decoder := xml.NewDecoder(bufio.NewReaderSize(reader, 64*1024))
	// Trust lists in the wild carry every encoding under the sun; asking Go to
	// decode whatever is declared avoids a hard failure on Latin-1 provider names.
	decoder.CharsetReader = charsetReader

	var (
		current      domain.TrustService
		inProvider   bool
		inService    bool
		depth        int
		certificates []*x509.Certificate
		territory    string
		schemeName   string
	)

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return domain.TrustList{}, fmt.Errorf("read trust list XML: %w", err)
		}

		switch element := token.(type) {
		case xml.StartElement:
			depth++
			switch element.Name.Local {
			case "TrustServiceProvider":
				inProvider = true
				current = domain.TrustService{}
			case "TSPService":
				inService = true
				certificates = nil
			case "ServiceTypeIdentifier":
				if text, err := readText(decoder); err == nil {
					current.ServiceType = serviceTypeName(text)
					// The /Q suffix is what marks a service as qualified:
					// CA/QC, TSA/QTST, EDS/Q, PSES/Q, QESValidation/Q.
					current.Qualified = isQualifiedServiceType(current.ServiceType)
				}
				depth--
			case "ServiceStatus":
				if text, err := readText(decoder); err == nil {
					current.Status = lastPathSegment(text)
				}
				depth--
			case "X509Certificate":
				if text, err := readText(decoder); err == nil {
					if parsed := parseBase64Certificate(text); parsed != nil {
						certificates = append(certificates, parsed)
					}
				}
				depth--
			case "Name":
				// Scheme name and provider name share the element name; the
				// difference is the parent, tracked through inProvider/inService.
				if text, err := readText(decoder); err == nil {
					text = strings.TrimSpace(text)
					switch {
					case !inProvider && schemeName == "" && isSchemeName(element):
						schemeName = text
					case inProvider && !inService && current.ProviderName == "":
						current.ProviderName = text
					case inService && current.ServiceName == "":
						current.ServiceName = text
					}
				}
				depth--
			case "SchemeTerritory":
				if text, err := readText(decoder); err == nil {
					if territory == "" {
						// The outermost SchemeTerritory is the list's own country;
						// later ones appear as trusted-list pointers for others.
						territory = strings.TrimSpace(text)
					}
				}
				depth--
			case "IssueDateTime":
				if text, err := readText(decoder); err == nil {
					if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(text)); err == nil {
						list.PublishedAt = parsed
					}
				}
				depth--
			case "NextUpdate":
				if text, err := readText(decoder); err == nil {
					if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(text)); err == nil {
						list.NextUpdate = parsed
					}
				}
				depth--
			}
		case xml.EndElement:
			depth--
			switch element.Name.Local {
			case "TSPService":
				if inService {
					current.Certificates = certificates
					list.Services = append(list.Services, current)
					inService = false
				}
			case "TrustServiceProvider":
				inProvider = false
			}
		}
	}

	list.Territory = territory
	list.SchemeName = schemeName
	return list, nil
}

// readText consumes the character data of the current element and its end tag.
func readText(decoder *xml.Decoder) (string, error) {
	var builder strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", err
		}
		switch element := token.(type) {
		case xml.CharData:
			builder.Write(element)
		case xml.EndElement:
			return builder.String(), nil
		case xml.StartElement:
			// Nested elements (localised names) are flattened: keep reading text.
			continue
		}
	}
}

// isQualifiedServiceType reports whether an ETSI service type is qualified.
//
// The naming is not fully regular across member states: CA/QC ends in QC,
// TSA/QTST in QTST, and the rest use a trailing /Q. Matching the published
// suffixes is more reliable than enumerating every URI.
func isQualifiedServiceType(serviceType string) bool {
	switch {
	case serviceType == "CA/QC":
		return true
	case strings.HasSuffix(serviceType, "/Q"):
		return true
	case serviceType == "TSA/QTST":
		return true
	}
	return false
}

// serviceTypeName maps the ETSI URI onto the short code used in reports.
//
// The path after /Svctype/ is significant as a whole: taking only the last
// segment turns "CA/QC" into "QC" and every qualification check silently fails.
func serviceTypeName(uri string) string {
	trimmed := strings.TrimSpace(uri)
	const marker = "/Svctype/"
	if index := strings.Index(trimmed, marker); index >= 0 {
		return trimmed[index+len(marker):]
	}
	return lastPathSegment(trimmed)
}

// lastPathSegment returns the final path component of a URI or identifier.
func lastPathSegment(value string) string {
	if index := strings.LastIndexAny(value, "/#"); index >= 0 && index+1 < len(value) {
		return value[index+1:]
	}
	return value
}

// isSchemeName reports whether a Name element belongs to the scheme information.
func isSchemeName(element xml.StartElement) bool {
	for _, attribute := range element.Attr {
		if attribute.Name.Local == "lang" && strings.HasPrefix(attribute.Value, "en") {
			return true
		}
	}
	return false
}

// parseBase64Certificate decodes one X509Certificate entry.
func parseBase64Certificate(text string) *x509.Certificate {
	cleaned := strings.Join(strings.Fields(text), "")
	der, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return certificate
}

// charsetReader tolerates the encodings found in real trust lists.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return input, nil
	}
	// Non-UTF-8 lists exist but are rare; reading the bytes as-is keeps the
	// provider names usable even if a few characters are mangled.
	return input, nil
}

// MustParseForTest is a helper for tests that need a parsed list from a literal.
// It lives in the package because the alternative is duplicating the parser in
// every test file; production code never calls it.
func MustParseForTest(content string, t interface{ Fatalf(string, ...any) }) domain.TrustList {
	list, err := TSLParser{}.Parse(strings.NewReader(content))
	if err != nil {
		t.Fatalf("parse trust list: %v", err)
	}
	return list
}
