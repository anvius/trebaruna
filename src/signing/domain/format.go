// Package domain holds the signing vocabulary: formats, levels, seals.
//
// No I/O, no crypto, no third-party imports. Pure vocabulary that a
// business stakeholder can read.
package domain

import "fmt"

// Format is an AdES signature format. It names the ETSI standard that the
// resulting artefact must satisfy.
type Format string

const (
	// Cades produces a .p7m CMS container (ETSI EN 319 122-1).
	Cades Format = "cades"

	// Pades produces a signed PDF (ETSI EN 319 142-1).
	Pades Format = "pades"

	// Xades produces a signed XML (ETSI EN 319 132-1).
	Xades Format = "xades"

	// Xmldsig produces a plain XML signature (W3C XML-Signature): no signed
	// properties, so no signing time, policy or timestamp. Kept for the
	// systems that still ask for it, as AutoFirma does.
	Xmldsig Format = "xmldsig"

	// Odf signs an OpenDocument file inside itself (OASIS ODF 1.2, Part 3): a
	// XAdES signature over every stream of the package, in
	// META-INF/documentsignatures.xml.
	Odf Format = "odf"
)

// IsXML reports an XML signature: XAdES or plain XMLDSig.
func (f Format) IsXML() bool { return f == Xades || f == Xmldsig }

// Extension is the file suffix the format produces, following the
// convention observed in existing signing tools.
func (f Format) Extension() string {
	switch f {
	case Cades:
		return ".p7m"
	case Pades:
		return ".pdf"
	case Xades, Xmldsig:
		return ".xml"
	}
	return ""
}

// Standard names the ETSI norm the artefact complies with.
func (f Format) Standard() string {
	switch f {
	case Cades:
		return "ETSI EN 319 122-1"
	case Pades:
		return "ETSI EN 319 142-1"
	case Xades:
		return "ETSI EN 319 132-1"
	case Xmldsig:
		return "W3C XML-Signature 1.1"
	case Odf:
		return "OASIS ODF 1.2 Part 3, XAdES (ETSI EN 319 132-1)"
	}
	return ""
}

// ParseFormat reads a format from its external name.
func ParseFormat(raw string) (Format, error) {
	switch Format(raw) {
	case Cades, Pades, Xades, Xmldsig, Odf:
		return Format(raw), nil
	}
	return "", fmt.Errorf("unknown signature format %q: use cades, pades, xades, xmldsig or odf", raw)
}

// Level is the AdES baseline level. It determines whether a timestamp
// and revocation material must be present.
type Level string

const (
	// BES is the basic signature: no timestamp, no revocation material.
	BES Level = "bes"

	// T adds a trusted timestamp proving existence at a point in time.
	T Level = "t"

	// LT adds embedded revocation material so the signature stays
	// verifiable after the CA services disappear.
	LT Level = "lt"

	// LTA adds archival timestamps on top of LT to protect the
	// revocation material itself over long periods.
	LTA Level = "lta"
)

// NeedsTimestamp reports whether the level requires a timestamp authority.
func (l Level) NeedsTimestamp() bool {
	return l == T || l == LT || l == LTA
}

// EmbedsRevocation reports whether revocation material must be embedded.
func (l Level) EmbedsRevocation() bool {
	return l == LT || l == LTA
}

// Archival reports whether the level protects revocation material over time.
func (l Level) Archival() bool {
	return l == LTA
}

// ParseLevel reads a level from its external name.
func ParseLevel(raw string) (Level, error) {
	switch Level(raw) {
	case BES, T, LT, LTA:
		return Level(raw), nil
	}
	return "", fmt.Errorf("unknown signature level %q: use bes, t, lt or lta", raw)
}
