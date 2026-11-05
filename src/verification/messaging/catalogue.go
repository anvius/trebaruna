// Package messaging holds every user-visible string of the verification report.
//
// Two surfaces render the same report: the CLI and the desktop app. Keeping the
// catalogue here means a finding is translated once, and the init check below
// guarantees no language silently falls back to English.
package messaging

import (
	"fmt"

	"codeberg.org/simplicer/firma-it/src/verification/domain"
)

// Catalogue holds every user-visible string of the verification report.
//
// Labels live in one struct per language rather than in a template, so the
// compiler catches a missing field: a report that silently falls back to English
// is worse than one that fails to build.
type Catalogue struct {
	LabelFormat      string
	LabelVerdict     string
	LabelSignature   string
	LabelSigner      string
	LabelIdentifier  string
	LabelIssuer      string
	LabelSignedAt    string
	LabelTimestamped string
	LabelIntegrity   string
	NoSignatures     string

	// Verdicts.
	VerdictQualified string
	VerdictAdvanced  string
	VerdictUntrusted string
	VerdictBroken    string
	VerdictUnknown   string

	// Statuses.
	StatusGood    string
	StatusWarn    string
	StatusBad     string
	StatusUnknown string

	// Findings, keyed by code. The English message from the report is the
	// fallback when a code is missing here.
	Findings map[string]string
}

var Spanish = Catalogue{
	LabelFormat:      "Formato",
	LabelVerdict:     "Veredicto",
	LabelSignature:   "Firma",
	LabelSigner:      "Firmante",
	LabelIdentifier:  "Identificador",
	LabelIssuer:      "Emisor",
	LabelSignedAt:    "Firmado",
	LabelTimestamped: "Sellado",
	LabelIntegrity:   "Integridad",
	NoSignatures:     "El documento no tiene firmas.",

	VerdictQualified: "cualificada",
	VerdictAdvanced:  "avanzada",
	VerdictUntrusted: "emisor no reconocido",
	VerdictBroken:    "alterada",
	VerdictUnknown:   "indeterminada",

	StatusGood:    "correcto",
	StatusWarn:    "atención",
	StatusBad:     "error",
	StatusUnknown: "sin verificar",

	Findings: map[string]string{
		"signature.intact":                     "el contenido firmado no se ha modificado",
		"signature.modified":                   "el documento cambió después de firmarse",
		"certificate.trusted":                  "el emisor es una autoridad reconocida",
		"certificate.untrusted_issuer":         "el emisor no está en ninguna lista de confianza",
		"certificate.self_signed":              "certificado autofirmado: criptografía válida, sin confianza de terceros",
		"certificate.missing":                  "la firma no incluye el certificado del firmante",
		"certificate.expired_now":              "el certificado ha caducado; ya no puede crear firmas nuevas",
		"certificate.expired_at_signing":       "el certificado ya había caducado cuando se firmó",
		"certificate.not_yet_valid_at_signing": "el certificado todavía no era válido cuando se firmó",
		"certificate.validity_unproven":        "la fecha de firma la declara el firmante y no está sellada",
		"certificate.revoked_before_signing":   "el certificado fue revocado antes de la firma",
		"certificate.revoked_after_signing":    "el certificado fue revocado después de la firma; la firma no se ve afectada",
		"certificate.revoked":                  "el certificado está revocado",
		"timestamp.invalid":                    "el sello de tiempo existe pero no verifica",
		"trustlist.unavailable":                "sin lista de confianza: los emisores solo se comprueban contra las raíces del sistema",
		"trustlist.stale":                      "la lista de confianza está caducada: ejecuta «firma-it trust sync»",
		"format.unsupported":                   "no hay verificador para este formato",
		"verification.warning":                 "aviso del verificador",
		"signature.qualified":                  "firma cualificada: certificado cualificado, dispositivo cualificado y emisor cualificado vigente",
		"signature.not_qualified":              "la firma es avanzada pero no cualificada",
	},
}

var Italian = Catalogue{
	LabelFormat:      "Formato",
	LabelVerdict:     "Esito",
	LabelSignature:   "Firma",
	LabelSigner:      "Firmatario",
	LabelIdentifier:  "Identificativo",
	LabelIssuer:      "Emittente",
	LabelSignedAt:    "Firmato",
	LabelTimestamped: "Marcato",
	LabelIntegrity:   "Integrità",
	NoSignatures:     "Il documento non contiene firme.",

	VerdictQualified: "qualificata",
	VerdictAdvanced:  "avanzata",
	VerdictUntrusted: "emittente non riconosciuto",
	VerdictBroken:    "alterata",
	VerdictUnknown:   "indeterminata",

	StatusGood:    "corretto",
	StatusWarn:    "attenzione",
	StatusBad:     "errore",
	StatusUnknown: "non verificato",

	Findings: map[string]string{
		"signature.intact":                     "il contenuto firmato non è stato modificato",
		"signature.modified":                   "il documento è cambiato dopo la firma",
		"certificate.trusted":                  "l'emittente è un'autorità riconosciuta",
		"certificate.untrusted_issuer":         "l'emittente non è in alcun elenco di fiducia",
		"certificate.self_signed":              "certificato autofirmato: crittografia valida, nessuna fiducia di terzi",
		"certificate.missing":                  "la firma non include il certificato del firmatario",
		"certificate.expired_now":              "il certificato è scaduto; non può più creare nuove firme",
		"certificate.expired_at_signing":       "il certificato era già scaduto al momento della firma",
		"certificate.not_yet_valid_at_signing": "il certificato non era ancora valido al momento della firma",
		"certificate.validity_unproven":        "la data della firma è dichiarata dal firmatario e non è marcata",
		"certificate.revoked_before_signing":   "il certificato è stato revocato prima della firma",
		"certificate.revoked_after_signing":    "il certificato è stato revocato dopo la firma; la firma resta valida",
		"certificate.revoked":                  "il certificato è revocato",
		"timestamp.invalid":                    "la marca temporale esiste ma non verifica",
		"trustlist.unavailable":                "nessun elenco di fiducia: gli emittenti sono confrontati solo con le radici di sistema",
		"trustlist.stale":                      "l'elenco di fiducia è scaduto: esegui «firma-it trust sync»",
		"format.unsupported":                   "nessun verificatore per questo formato",
		"verification.warning":                 "avviso del verificatore",
		"signature.qualified":                  "firma qualificata: certificato qualificato, dispositivo qualificato ed emittente qualificato vigente",
		"signature.not_qualified":              "la firma è avanzata ma non qualificata",
	},
}

var English = Catalogue{
	LabelFormat:      "Format",
	LabelVerdict:     "Verdict",
	LabelSignature:   "Signature",
	LabelSigner:      "Signer",
	LabelIdentifier:  "Identifier",
	LabelIssuer:      "Issuer",
	LabelSignedAt:    "Signed",
	LabelTimestamped: "Timestamped",
	LabelIntegrity:   "Integrity",
	NoSignatures:     "The document has no signatures.",

	VerdictQualified: "qualified",
	VerdictAdvanced:  "advanced",
	VerdictUntrusted: "untrusted issuer",
	VerdictBroken:    "tampered",
	VerdictUnknown:   "undetermined",

	StatusGood:    "ok",
	StatusWarn:    "warning",
	StatusBad:     "error",
	StatusUnknown: "unverified",

	Findings: map[string]string{
		"signature.intact":                     "the signed content is unaltered",
		"signature.modified":                   "the document changed after it was signed",
		"certificate.trusted":                  "the issuer is a recognised authority",
		"certificate.untrusted_issuer":         "the issuer is not in any trust list",
		"certificate.self_signed":              "self-signed certificate: valid cryptography, no third-party trust",
		"certificate.missing":                  "the signature does not embed the signing certificate",
		"certificate.expired_now":              "the certificate has expired; it can no longer create new signatures",
		"certificate.expired_at_signing":       "the certificate had already expired when the signature was made",
		"certificate.not_yet_valid_at_signing": "the certificate was not valid yet when the signature was made",
		"certificate.validity_unproven":        "the signing time is declared by the signer and is not timestamped",
		"certificate.revoked_before_signing":   "the certificate was revoked before signing",
		"certificate.revoked_after_signing":    "the certificate was revoked after signing; the signature is unaffected",
		"certificate.revoked":                  "the certificate is revoked",
		"timestamp.invalid":                    "the timestamp token exists but does not verify",
		"trustlist.unavailable":                "no trust list: issuers are checked against the system roots only",
		"trustlist.stale":                      "the trust list is out of date: run 'firma-it trust sync'",
		"format.unsupported":                   "no verifier is available for this format",
		"verification.warning":                 "verifier warning",
		"signature.qualified":                  "qualified signature: qualified certificate, qualified device and a currently granted qualified issuer",
		"signature.not_qualified":              "the signature is advanced but not qualified",
	},
}

// VerdictName renders a trust level.
func (c Catalogue) VerdictName(level domain.TrustLevel) string {
	switch level {
	case domain.TrustQualified:
		return c.VerdictQualified
	case domain.TrustAdvanced:
		return c.VerdictAdvanced
	case domain.TrustUntrusted:
		return c.VerdictUntrusted
	case domain.TrustBroken:
		return c.VerdictBroken
	}
	return c.VerdictUnknown
}

// StatusName renders a status.
func (c Catalogue) StatusName(status domain.Status) string {
	switch status {
	case domain.StatusGood:
		return c.StatusGood
	case domain.StatusWarn:
		return c.StatusWarn
	case domain.StatusBad:
		return c.StatusBad
	}
	return c.StatusUnknown
}

// StatusMark returns the glyph shown before a finding.
func (c Catalogue) StatusMark(status domain.Status) string {
	switch status {
	case domain.StatusBad:
		return "✗"
	case domain.StatusWarn:
		return "!"
	case domain.StatusUnknown:
		return "?"
	}
	return "✓"
}

// FindingName translates a finding code, falling back to the English message.
func (c Catalogue) FindingName(code, fallback string) string {
	if translated, ok := c.Findings[code]; ok {
		return translated
	}
	return fallback
}

// compile-time guard: every language must define every finding code.
func init() {
	required := []string{
		"signature.intact", "signature.modified", "certificate.trusted",
		"certificate.untrusted_issuer", "certificate.self_signed", "certificate.missing",
		"certificate.expired_now", "certificate.expired_at_signing",
		"certificate.not_yet_valid_at_signing", "certificate.validity_unproven",
		"certificate.revoked_before_signing", "certificate.revoked_after_signing",
		"certificate.revoked", "timestamp.invalid", "trustlist.unavailable",
		"trustlist.stale", "format.unsupported", "verification.warning",
		"signature.qualified", "signature.not_qualified",
	}

	for name, catalogue := range map[string]Catalogue{
		"es": Spanish, "it": Italian, "en": English,
	} {
		for _, code := range required {
			if _, ok := catalogue.Findings[code]; !ok {
				panic(fmt.Sprintf("catalogue %s is missing the finding %q", name, code))
			}
		}
	}
}

// For picks a language from a locale string.
func For(locale string) Catalogue {
	switch {
	case len(locale) >= 2 && (locale[:2] == "it" || locale[:2] == "It" || locale[:2] == "IT"):
		return Italian
	case len(locale) >= 2 && (locale[:2] == "en" || locale[:2] == "En" || locale[:2] == "EN"):
		return English
	}
	return Spanish
}
