package domain

// Single signatures through the site's server, the "…tri" formats (E.8):
// the server prepares what is signed, the person's key signs it here, the
// server assembles the signature and keeps it, answering with its id.

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
)

// TriphaseCall is one call to a site's triphase signing service.
type TriphaseCall struct {
	// Step is "pre" or "post".
	Step      string
	Crypto    Operation
	Format    Format
	Algorithm string
	// Chain is the signer's certificate first.
	Chain [][]byte
	// Document is the page's dat: the id of the document on the server.
	Document   []byte
	Properties map[string]string
	// Session is the triphase data with the client's signatures, for post.
	Session []byte
}

// triphaseFormats are the names the service takes, by family.
var triphaseFormats = map[string]string{"cades": "CAdES", "xades": "XAdES", "pades": "PAdES", "facturae": "FacturaE", "none": "NONE"}

// Body writes the form the service reads (E.8), in AutoFirma's order and,
// as AutoFirma does, without percent-encoding (every value is URL-safe):
// op, cop, format, algo, cert (URL-safe Base64, joined by commas; the
// signer's alone when includeOnlySignningCertificate is true), doc, params
// (the properties but serverUrl and documentId) and, for post, session.
func (c TriphaseCall) Body() string {
	chain := c.Chain
	if strings.EqualFold(c.Properties["includeOnlySignningCertificate"], "true") && len(chain) > 1 {
		chain = chain[:1]
	}
	certificates := make([]string, len(chain))
	for index, certificate := range chain {
		certificates[index] = base64.URLEncoding.EncodeToString(certificate)
	}
	fields := []string{
		"op=" + c.Step,
		"cop=" + string(c.Crypto),
		"format=" + triphaseFormats[c.Format.Family],
		"algo=" + url.QueryEscape(c.Algorithm),
		"cert=" + strings.Join(certificates, ","),
		"doc=" + base64.URLEncoding.EncodeToString(c.Document),
	}
	params := map[string]string{}
	for key, value := range c.Properties {
		if key != "serverUrl" && key != "documentId" {
			params[key] = value
		}
	}
	if len(params) > 0 {
		fields = append(fields, "params="+base64.URLEncoding.EncodeToString([]byte(EncodeProperties(params))))
	}
	if c.Session != nil {
		fields = append(fields, "session="+base64.URLEncoding.EncodeToString(c.Session))
	}
	return strings.Join(fields, "&")
}

// ReadTriphasePre reads the pre answer: URL-safe Base64 of the triphase
// XML, or the service's error ("ERR-…"; "ERR-21:" asks for a confirmation
// trebaruna does not give).
func ReadTriphasePre(answer []byte) (TriphaseData, error) {
	text := strings.TrimSpace(string(answer))
	if strings.HasPrefix(text, "ERR-") {
		return TriphaseData{}, Failure{Code: ContactBatchService, Cause: text}
	}
	decoded, err := DecodeBase64(text)
	if err != nil {
		return TriphaseData{}, Failure{Code: ContactBatchService, Cause: "unreadable pre-sign answer"}
	}
	data, err := ReadTriphaseXML(decoded)
	if err != nil {
		return TriphaseData{}, err
	}
	if len(data.Signs) == 0 {
		return TriphaseData{}, Failure{Code: SignatureFailed, Cause: "the site's server prepared nothing to sign"}
	}
	return data, nil
}

// ReadTriphasePost reads "OK NEWID=<URL-safe Base64 id>": the id of the
// signature the server keeps, which is what the page receives.
func ReadTriphasePost(answer []byte) ([]byte, error) {
	text := strings.TrimSpace(string(answer))
	encoded, found := strings.CutPrefix(text, "OK NEWID=")
	if !found {
		return nil, Failure{Code: ContactBatchService, Cause: text}
	}
	id, err := DecodeBase64(encoded)
	if err != nil {
		return nil, Failure{Code: ContactBatchService, Cause: "unreadable signature id"}
	}
	return id, nil
}

// EncodeProperties writes properties as a Java .properties text, the form
// AutoFirma's servers read: one key=value per line, in key order, with
// backslashes, line breaks, and the separators of a key escaped.
func EncodeProperties(properties map[string]string) string {
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var out bytes.Buffer
	for _, key := range keys {
		out.WriteString(escapeProperty(key, true) + "=" + escapeProperty(properties[key], false) + "\n")
	}
	return out.String()
}

func escapeProperty(text string, key bool) string {
	var out strings.Builder
	for _, character := range text {
		switch {
		case character == '\\':
			out.WriteString(`\\`)
		case character == '\n':
			out.WriteString(`\n`)
		case character == '\r':
			out.WriteString(`\r`)
		case key && (character == '=' || character == ':' || character == ' '):
			out.WriteString(`\` + string(character))
		default:
			out.WriteRune(character)
		}
	}
	return out.String()
}
