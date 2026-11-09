// Package domain describes what the desktop window offers, in business terms.
//
// It has no Fyne, no filesystem and no subprocess: the window is a deliverable
// of the signing slice, so its model must stay independent of the toolkit.
package domain

import (
	"fmt"
	"strings"
)

// SigningIntent is everything the user filled in before pressing Sign.
type SigningIntent struct {
	DocumentPath string
	KeyPath      string
	Passphrase   string
	Format       string
	Level        string
	Page         int
	Box          string
	TimestampURL string
	Reason       string
	Location     string
}

// Validate reports what is missing, before any process is spawned.
//
// A desktop app that silently launches a failing subprocess is worse than one
// that refuses up front, so every requirement the CLI enforces is checked here
// as well, with a message the user can act on.
//
// Errors carry a code, not a sentence: the window renders them in the user's
// language, so the same validation serves Spanish, Italian and English.
func (i SigningIntent) Validate() error {
	if strings.TrimSpace(i.DocumentPath) == "" {
		return Problem{Code: ProblemMissingDocument}
	}
	if strings.TrimSpace(i.KeyPath) == "" {
		return Problem{Code: ProblemMissingKey}
	}
	if (i.Level == "t" || i.Level == "lt") && strings.TrimSpace(i.TimestampURL) == "" {
		return Problem{Code: ProblemMissingTSA, Detail: i.Level}
	}
	if i.Box != "" {
		if _, err := ParseBox(i.Box); err != nil {
			return err
		}
	}
	if i.Page < 1 {
		return Problem{Code: ProblemInvalidPage}
	}
	return nil
}

// Box is a seal rectangle in PDF points.
type Box struct {
	LowerLeftX  float64
	LowerLeftY  float64
	UpperRightX float64
	UpperRightY float64
}

// ParseBox reads the "x1,y1,x2,y2" syntax used by the CLI, so both surfaces
// accept exactly the same input.
func ParseBox(raw string) (Box, error) {
	parts := strings.Split(raw, ",")
	if len(parts) != 4 {
		return Box{}, fmt.Errorf("el hueco necesita cuatro números: x1,y1,x2,y2")
	}
	var values [4]float64
	for index, part := range parts {
		trimmed := strings.TrimSpace(part)
		var value float64
		if _, err := fmt.Sscanf(trimmed, "%f", &value); err != nil {
			return Box{}, fmt.Errorf("%q no es un número", trimmed)
		}
		values[index] = value
	}
	if values[2] <= values[0] {
		return Box{}, fmt.Errorf("el borde derecho debe ser mayor que el izquierdo")
	}
	if values[3] <= values[1] {
		return Box{}, fmt.Errorf("el borde superior debe ser mayor que el inferior")
	}
	return Box{values[0], values[1], values[2], values[3]}, nil
}

// OutputName predicts the signed file name, using the same convention as the
// signing domain, so the window can say where the result will land before the
// user presses Sign.
func (i SigningIntent) OutputName() string {
	switch i.Format {
	case "cades":
		return i.DocumentPath + ".p7m"
	case "xades":
		return trimExtension(i.DocumentPath) + "_signed.xml"
	default:
		return trimExtension(i.DocumentPath) + "_signed.pdf"
	}
}

// trimExtension removes the last dot-suffix.
func trimExtension(path string) string {
	dot := strings.LastIndex(path, ".")
	slash := strings.LastIndexAny(path, "/\\")
	if dot <= slash {
		return path
	}
	return path[:dot]
}

// Receipt is what a completed signature hands back to the user: the file that
// now exists and the facts worth repeating about it.
type Receipt struct {
	SignedPath string
	// Standard names the profile, e.g. "PAdES-B-T", as the signer reported it.
	Standard string
	Signer   string
	// SignedAt is the instant printed in the seal, in RFC 3339.
	SignedAt   string
	SealCount  int
	SelfSigned bool
}

// ProblemCode identifies a validation failure without tying it to a language.
type ProblemCode string

const (
	// ProblemMissingDocument means no file was chosen.
	ProblemMissingDocument ProblemCode = "missing_document"

	// ProblemMissingKey means no certificate was chosen.
	ProblemMissingKey ProblemCode = "missing_key"

	// ProblemMissingTSA means the level needs an authority that was not given.
	ProblemMissingTSA ProblemCode = "missing_tsa"

	// ProblemInvalidPage means the page number is below one.
	ProblemInvalidPage ProblemCode = "invalid_page"

	// ProblemInvalidBox means the seal rectangle is malformed.
	ProblemInvalidBox ProblemCode = "invalid_box"

	// ProblemNoOutput means the signer reported success but the signed file is
	// not on disk.
	ProblemNoOutput ProblemCode = "no_output"
)

// Problem is a translatable validation error.
type Problem struct {
	Code   ProblemCode
	Detail string
}

// Error implements error, for logs and tests.
func (p Problem) Error() string {
	if p.Detail != "" {
		return string(p.Code) + ": " + p.Detail
	}
	return string(p.Code)
}
