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

	// FormatODF signs inside an OpenDocument file, as LibreOffice does.
	FormatODF SignatureFormat = "odf"

	// FormatOOXML signs inside a Word, Excel or PowerPoint file, as
	// Microsoft Office does.
	FormatOOXML SignatureFormat = "ooxml"

	// FormatCAdESDetached writes a .p7s beside the document, which stays
	// untouched.
	FormatCAdESDetached SignatureFormat = "cades-detached"

	// FormatCosign adds a parallel signature to an existing envelope.
	FormatCosign SignatureFormat = "cosign"

	// FormatCountersign counter-signs the signatures of an existing envelope.
	FormatCountersign SignatureFormat = "countersign"

	// FormatEach signs every document of a batch in its own conventional
	// format: signed PDF, signed XML, .p7m for anything else.
	FormatEach SignatureFormat = "each"
)

// BatchFormats lists what a batch can be signed as.
func BatchFormats() []SignatureFormat {
	return []SignatureFormat{FormatEach, FormatCAdES, FormatCAdESDetached}
}

// For resolves the batch choice for one document.
func (f SignatureFormat) For(documentPath string) SignatureFormat {
	if f == FormatEach {
		return FormatsFor(documentPath)[0]
	}
	return f
}

// FormatsFor lists the formats that make sense for a document, the
// conventional one first. A PDF or an XML may also go in a .p7m envelope,
// which some Italian offices still require; anything else only fits there.
func FormatsFor(documentPath string) []SignatureFormat {
	switch strings.ToLower(filepath.Ext(documentPath)) {
	case ".p7m":
		// An envelope gets one more signature beside the others, a signature
		// over theirs, or — the old way — another envelope around it.
		return []SignatureFormat{FormatCosign, FormatCountersign, FormatCAdES}
	case ".p7s":
		return []SignatureFormat{FormatCosign, FormatCountersign}
	case ".asics", ".asice", ".scs", ".sce":
		// A container takes a parallel signature of the kind it holds.
		return []SignatureFormat{FormatCosign}
	case ".pdf":
		return []SignatureFormat{FormatPAdES, FormatCAdES, FormatCAdESDetached}
	case ".xml":
		return []SignatureFormat{FormatXAdES, FormatCAdES, FormatCAdESDetached}
	case ".odt", ".ods", ".odp", ".odg", ".odf", ".odm", ".ott", ".ots", ".otp", ".otg":
		return []SignatureFormat{FormatODF, FormatCAdES, FormatCAdESDetached}
	case ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
		".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm":
		return []SignatureFormat{FormatOOXML, FormatCAdES, FormatCAdESDetached}
	}
	return []SignatureFormat{FormatCAdES, FormatCAdESDetached}
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
