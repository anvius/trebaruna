// Package report writes a verification as a document a person can keep or
// send: Markdown, HTML or PDF. The three say the same thing, built once from
// the verification and the catalogue of the person's language, so a reader
// of the PDF and a reader of the Markdown see the same findings.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"codeberg.org/simplicer/trebaruna/src/verification/messaging"
)

// Input is what a report states.
type Input struct {
	Report    domain.DocumentReport
	Catalogue messaging.Catalogue
	// Language is the report's language tag (es, ca, gl, eu, it, pl, en), for
	// HTML.
	Language string
	// Digest is the SHA-256 of the verified file, hexadecimal: it ties the
	// report to the exact bytes checked.
	Digest string
	// Tool names the program and its version.
	Tool string
	// Network lists the connections the verification made (ADR-0010).
	Network []transparency.Connection
}

// Format is a report's file format.
type Format string

const (
	Markdown Format = "markdown"
	HTML     Format = "html"
	PDF      Format = "pdf"
)

// FormatFor reads the format from a file name's suffix.
func FormatFor(path string) (Format, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".markdown":
		return Markdown, nil
	case ".html", ".htm":
		return HTML, nil
	case ".pdf":
		return PDF, nil
	}
	return "", fmt.Errorf("a report is .md, .html or .pdf, not %q", filepath.Ext(path))
}

// Render writes the report in the format.
func Render(format Format, input Input) ([]byte, error) {
	document := withoutHome(build(input))
	switch format {
	case Markdown:
		return renderMarkdown(document), nil
	case HTML:
		return renderHTML(document, input.Language), nil
	case PDF:
		return renderPDF(document, input.Report.VerifiedAt)
	}
	return nil, fmt.Errorf("unknown report format %q", format)
}

// row is a label and its value.
type row struct{ label, value string }

// section is a heading, its rows, and a list under a label of its own.
type section struct {
	heading   string
	rows      []row
	listLabel string
	list      []string
}

// document is the report's content, independent of its format.
type document struct {
	title    string
	sections []section
	note     string
}

// timeLayout writes instants with their offset, unambiguous in any zone.
const timeLayout = "2006-01-02 15:04:05 -07:00"

// build turns the verification into the report's content.
func build(input Input) document {
	catalogue, report := input.Catalogue, input.Report
	summary := section{
		heading: filepath.Base(report.Path),
		rows: []row{
			{catalogue.LabelDocument, report.Path},
			{"SHA-256", input.Digest},
			{catalogue.LabelFormat, report.Format},
			{catalogue.LabelVerdict, catalogue.VerdictName(report.Verdict())},
			{catalogue.LabelVerifiedAt, report.VerifiedAt.Format(timeLayout)},
			{catalogue.LabelTool, input.Tool},
		},
	}
	if !report.Signed || len(report.Signers) == 0 {
		summary.list = []string{catalogue.NoSignatures}
	}
	content := document{title: catalogue.ReportTitle, sections: []section{summary}, note: catalogue.ReportNote}

	for index, signer := range report.Signers {
		signature := section{heading: fmt.Sprintf("%s %d — %s", catalogue.LabelSignature, index+1, signer.FieldName)}
		signature.rows = append(signature.rows, row{catalogue.LabelSigner, signer.SignerName})
		if signer.Identifier != "" {
			signature.rows = append(signature.rows, row{catalogue.LabelIdentifier, signer.Identifier})
		}
		if signer.Issuer != "" {
			signature.rows = append(signature.rows, row{catalogue.LabelIssuer, signer.Issuer})
		}
		if !signer.NotBefore.IsZero() && !signer.NotAfter.IsZero() {
			signature.rows = append(signature.rows, row{catalogue.LabelValidity,
				signer.NotBefore.Format(timeLayout) + " – " + signer.NotAfter.Format(timeLayout)})
		}
		if !signer.SignedAt.IsZero() {
			label := catalogue.LabelSignedAt
			if signer.Timestamped {
				label = catalogue.LabelTimestamped
			}
			signature.rows = append(signature.rows, row{label, signer.SignedAt.Local().Format(timeLayout)})
		}
		for _, declared := range catalogue.DeclarationRows(signer.Declared) {
			signature.rows = append(signature.rows, row{declared[0], declared[1]})
		}
		signature.rows = append(signature.rows,
			row{catalogue.LabelFormat, signer.Format},
			row{catalogue.LabelIntegrity, catalogue.StatusName(signer.Integrity)},
			row{catalogue.LabelTrust, catalogue.VerdictName(signer.Trust)})
		signature.listLabel = catalogue.LabelFindings
		signature.list = findingLines(catalogue, signer.Findings)
		content.sections = append(content.sections, signature)
	}

	if len(report.Warnings) > 0 {
		content.sections = append(content.sections, section{
			heading: catalogue.LabelFindings, list: findingLines(catalogue, report.Warnings),
		})
	}

	connections := section{heading: catalogue.LabelConnections}
	for _, connection := range input.Network {
		line := fmt.Sprintf("%s: %s %s", connection.Purpose, connection.Method, connection.URL)
		if connection.Status != 0 {
			line += fmt.Sprintf(" (%d)", connection.Status)
		}
		if connection.Error != "" {
			line += " — " + connection.Error
		}
		connections.list = append(connections.list, line)
	}
	if len(connections.list) == 0 {
		connections.list = []string{catalogue.NoConnections}
	}
	content.sections = append(content.sections, connections)
	return content
}

// withoutHome writes the person's home directory as ~ wherever a path
// shows it: a report is made to be sent, and the account name is not part
// of the evidence.
func withoutHome(content document) document {
	home, err := os.UserHomeDir()
	if err != nil || len(home) < 2 {
		return content
	}
	hide := func(text string) string { return strings.ReplaceAll(text, home, "~") }
	for index := range content.sections {
		part := &content.sections[index]
		part.heading = hide(part.heading)
		for position := range part.rows {
			part.rows[position].value = hide(part.rows[position].value)
		}
		for position := range part.list {
			part.list[position] = hide(part.list[position])
		}
	}
	return content
}

// findingLines writes each finding as its status, its text in the person's
// language and, when there is one, its detail.
func findingLines(catalogue messaging.Catalogue, findings []domain.Finding) []string {
	lines := make([]string, 0, len(findings))
	for _, finding := range findings {
		line := catalogue.StatusName(finding.Status) + ": " + catalogue.FindingName(finding.Code, finding.Message)
		if finding.Detail != "" {
			line += " (" + finding.Detail + ")"
		}
		lines = append(lines, line)
	}
	return lines
}

// verifiedAt is the instant a report was made; zero means now.
func verifiedAt(at time.Time) time.Time {
	if at.IsZero() {
		return time.Now()
	}
	return at
}
