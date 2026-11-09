// Package domain describes what the desktop window offers, in business terms.
//
// It has no Fyne, no filesystem and no subprocess: the window is a deliverable
// of the signing slice, so its model must stay independent of the toolkit.
package domain

import (
	"strings"

	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
)

// SigningIntent is everything the user filled in before pressing Sign.
type SigningIntent struct {
	DocumentPath string
	Key          CertificateFile
	// Card is the certificate on a card to sign with; when chosen it replaces
	// Key.
	Card   CardKey
	Format SignatureFormat
	Level  SignatureLevel
	Seal   SealChoice
	// Invisible signs a PDF without any mark on its pages; Seal is ignored.
	Invisible    bool
	TimestampURL string
	// TimestampUser and TimestampPassword are the account some authorities
	// require (Aruba's and InfoCert's, among others). Both may be empty.
	TimestampUser     string
	TimestampPassword string
	Reason            string
	Location          string
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
	if i.Card.Chosen() {
		if err := i.Card.problem(); err != nil {
			return err
		}
	} else if strings.TrimSpace(i.Key.Path) == "" {
		return Problem{Code: ProblemMissingKey}
	}
	if i.Level.NeedsTimestamp() && strings.TrimSpace(i.TimestampURL) == "" {
		return Problem{Code: ProblemMissingTSA, Detail: string(i.Level)}
	}
	if i.Seal.Page < 1 {
		return Problem{Code: ProblemInvalidPage}
	}
	return nil
}

// SealChoice is where the user put the visible seal.
//
// A choice without a rectangle is legitimate: with no preview (poppler is
// missing, or the format is not PDF) the signer applies its default corner.
type SealChoice struct {
	// Page is 1-based.
	Page int
	Rect SealRect
}

// Placed reports whether the user chose a rectangle on the page.
func (c SealChoice) Placed() bool {
	return c.Rect.Width() > 0 && c.Rect.Height() > 0
}

// OutputName predicts the signed file name, using the same convention as the
// signing domain, so the window can say where the result will land before the
// user presses Sign.
func (i SigningIntent) OutputName() string {
	switch i.Format {
	case FormatCAdES:
		return i.DocumentPath + ".p7m"
	case FormatCAdESDetached:
		return i.DocumentPath + ".p7s"
	case FormatCosign:
		return addedSignatureName(i.DocumentPath, "cosigned")
	case FormatCountersign:
		return addedSignatureName(i.DocumentPath, "countersigned")
	case FormatXAdES:
		return trimExtension(i.DocumentPath) + "_signed.xml"
	default:
		return trimExtension(i.DocumentPath) + "_signed.pdf"
	}
}

// addedSignatureName mirrors the signer's naming for an envelope that gained a
// signature: the marker goes before the last extension.
func addedSignatureName(path, marker string) string {
	return trimExtension(path) + "_" + marker + path[len(trimExtension(path)):]
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
	// DocumentDigest and SignedDigest are the SHA-256 of the document signed
	// and of the file written, as the signer measured them.
	DocumentDigest string
	SignedDigest   string
	// Network is every connection the signature needed (ADR-0010).
	Network []transparency.Connection
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

	// ProblemNoOutput means the signer reported success but the signed file is
	// not on disk.
	ProblemNoOutput ProblemCode = "no_output"

	// ProblemLockedCertificate means the passphrase does not open the
	// certificate file.
	ProblemLockedCertificate ProblemCode = "locked_certificate"

	// ProblemMissingPIN means a card was chosen and its PIN not typed.
	ProblemMissingPIN ProblemCode = "missing_pin"

	// ProblemWrongPIN means the card refused the PIN and counted an attempt.
	// Detail carries what the card says about the next one.
	ProblemWrongPIN ProblemCode = "wrong_pin"

	// ProblemCardLocked means the card takes no PIN until its PUK unlocks it.
	ProblemCardLocked ProblemCode = "card_locked"

	// ProblemPINExpired means the card wants its PIN set or changed first.
	ProblemPINExpired ProblemCode = "pin_expired"

	// ProblemMissingPUK means an unlock was asked without the PUK.
	ProblemMissingPUK ProblemCode = "missing_puk"

	// ProblemWrongPUK means the card refused the PUK; Detail carries what the
	// card says about the next attempt.
	ProblemWrongPUK ProblemCode = "wrong_puk"

	// ProblemPUKLocked means only the card's issuer can unlock it now.
	ProblemPUKLocked ProblemCode = "puk_locked"

	// ProblemPINMismatch means the new PIN and its repetition differ.
	ProblemPINMismatch ProblemCode = "pin_mismatch"

	// ProblemNewPINRejected means the card cannot take the new PIN; Detail
	// carries the card's limits as the command stated them.
	ProblemNewPINRejected ProblemCode = "new_pin_rejected"

	// ProblemMissingSaveTo means a page asked to save a file and no place
	// was chosen.
	ProblemMissingSaveTo ProblemCode = "missing_save_to"
)

// StopsCard reports whether the problem forbids trying the card again with
// the same PIN: in a batch, the next document would spend another attempt.
func (p Problem) StopsCard() bool {
	switch p.Code {
	case ProblemMissingPIN, ProblemWrongPIN, ProblemCardLocked, ProblemPINExpired,
		ProblemMissingPUK, ProblemWrongPUK, ProblemPUKLocked:
		return true
	}
	return false
}

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
