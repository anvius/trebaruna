package domain

import (
	"path/filepath"
	"strings"
)

// SignatureFormat is the container a signature travels in.
type SignatureFormat string

const (
	// FormatPAdES signs inside the PDF: any PDF reader shows it.
	FormatPAdES SignatureFormat = "pades"

	// FormatCAdES wraps any file in a .p7m envelope.
	FormatCAdES SignatureFormat = "cades"

	// FormatXAdES signs inside an XML document.
	FormatXAdES SignatureFormat = "xades"
)

// FormatsFor lists the formats that make sense for a document, the
// conventional one first. A PDF or an XML may also go in a .p7m envelope,
// which some Italian offices still require; anything else only fits there.
func FormatsFor(documentPath string) []SignatureFormat {
	switch strings.ToLower(filepath.Ext(documentPath)) {
	case ".pdf":
		return []SignatureFormat{FormatPAdES, FormatCAdES}
	case ".xml":
		return []SignatureFormat{FormatXAdES, FormatCAdES}
	}
	return []SignatureFormat{FormatCAdES}
}

// HasVisibleSeal reports whether the format puts a mark on a page.
func (f SignatureFormat) HasVisibleSeal() bool { return f == FormatPAdES }

// SignatureLevel is how much evidence the signature carries over time.
type SignatureLevel string

const (
	// LevelBasic is the signature alone (B-B / BES).
	LevelBasic SignatureLevel = "bes"

	// LevelTimestamp adds a timestamp that proves when it was made (T).
	LevelTimestamp SignatureLevel = "t"

	// LevelLongTerm also embeds the revocation evidence (LT).
	LevelLongTerm SignatureLevel = "lt"

	// LevelArchive adds an archive timestamp over everything (LTA).
	LevelArchive SignatureLevel = "lta"
)

// Levels lists every level, weakest first.
func Levels() []SignatureLevel {
	return []SignatureLevel{LevelBasic, LevelTimestamp, LevelLongTerm, LevelArchive}
}

// NeedsTimestamp reports whether the level requires a timestamp authority.
func (l SignatureLevel) NeedsTimestamp() bool { return l != LevelBasic }

// NeedsRevocation reports whether the level embeds revocation evidence, which
// means asking the certificate's OCSP responder at signing time.
func (l SignatureLevel) NeedsRevocation() bool {
	return l == LevelLongTerm || l == LevelArchive
}
