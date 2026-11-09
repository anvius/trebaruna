package domain

import "strings"

// Format is a signature format a page names, as trebaruna understands it.
type Format struct {
	// Family is cades, xades, xmldsig, pades, facturae, odf, ooxml or none
	// (a bare PKCS#1 signature); empty for "auto".
	Family string
	// Packaging is the XAdES variant (enveloped, enveloping, detached) or the
	// ASiC container (asic-s), empty when the family decides.
	Packaging string
	// Triphase marks the "…tri" formats, signed through the site's server.
	Triphase bool
	// Name is the page's own spelling, for messages.
	Name string
}

// Auto reports "auto": the data decide (A.9).
func (f Format) Auto() bool { return f.Family == "" }

// ParseFormat maps AutoFirma's names (case-insensitive) onto trebaruna's
// formats; names trebaruna does not sign answer SAF_06.
func ParseFormat(name string) (Format, error) {
	lower := strings.ToLower(strings.TrimSpace(name))
	formats := map[string]Format{
		"auto":                       {},
		"cades":                      {Family: "cades"},
		"cms/pkcs#7":                 {Family: "cades"},
		"cadestri":                   {Family: "cades", Triphase: true},
		"cades-asic-s":               {Family: "cades", Packaging: "asic-s"},
		"xades":                      {Family: "xades"},
		"xades enveloped":            {Family: "xades", Packaging: "enveloped"},
		"xades enveloping":           {Family: "xades", Packaging: "enveloping"},
		"xades detached":             {Family: "xades", Packaging: "detached"},
		"xadestri":                   {Family: "xades", Triphase: true},
		"xades-asic-s":               {Family: "xades", Packaging: "asic-s"},
		"xmldsig":                    {Family: "xmldsig"},
		"xmldsig enveloped":          {Family: "xmldsig", Packaging: "enveloped"},
		"xmldsig enveloping":         {Family: "xmldsig", Packaging: "enveloping"},
		"xmldsig detached":           {Family: "xmldsig", Packaging: "detached"},
		"pades":                      {Family: "pades"},
		"adobe pdf":                  {Family: "pades"},
		"padestri":                   {Family: "pades", Triphase: true},
		"facturae":                   {Family: "facturae"},
		"odf":                        {Family: "odf"},
		"odf (open document format)": {Family: "odf"},
		"ooxml":                      {Family: "ooxml"},
		"ooxml (office open xml)":    {Family: "ooxml"},
		"factura-e":                  {Family: "facturae"},
		"none":                       {Family: "none"},
		"nonetri":                    {Family: "none", Triphase: true},
	}
	format, known := formats[lower]
	if !known {
		return Format{}, Failure{Code: UnsupportedFormat, Cause: name}
	}
	format.Name = name
	return format, nil
}

// signatureAlgorithms are the exact, case-sensitive names a page may send (A.6).
var signatureAlgorithms = map[string]bool{
	"SHA1": true, "SHA256": true, "SHA384": true, "SHA512": true,
	"SHA1withRSA": true, "SHA256withRSA": true, "SHA384withRSA": true, "SHA512withRSA": true,
	"SHA1withECDSA": true, "SHA256withECDSA": true, "SHA384withECDSA": true, "SHA512withECDSA": true,
}

// DigestOf keeps the digest part of an algorithm name: AutoFirma recomputes
// the rest from the key type (A.9).
func DigestOf(algorithm string) string {
	if at := strings.Index(algorithm, "with"); at > 0 {
		return algorithm[:at]
	}
	return algorithm
}
