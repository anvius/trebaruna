// Package messaging holds every user-visible string of the verification report.
//
// Two surfaces render the same report: the CLI and the desktop app. Keeping the
// catalogue here means a finding is translated once, and the init check below
// guarantees no language silently falls back to English.
package messaging

import (
	"fmt"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
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
	LabelPolicy      string
	LabelRoles       string
	LabelPlace       string
	LabelReason      string
	NoSignatures     string

	// The exported report (verify --report).
	ReportTitle     string
	LabelDocument   string
	LabelVerifiedAt string
	LabelTool       string
	LabelValidity   string
	LabelTrust      string

	// The certificate command: its validity period and state.
	LabelValidPeriod    string
	LabelState          string
	CertificateExpired  string // %d days ago
	CertificateExpiring string // in %d days
	CertificateValid    string // %d days left
	LabelFindings       string
	LabelConnections    string
	NoConnections       string
	ReportNote          string

	// Verdicts.
	VerdictQualified string
	VerdictAdvanced  string
	VerdictUntrusted string
	VerdictInvalid   string
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

	// Issuers says why a certificate's issuer is trusted or not, keyed by
	// the trust verdict's code; the qualified one names the list's
	// territory (%s).
	Issuers map[string]string
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
	LabelPolicy:      "Política",
	LabelRoles:       "Rol",
	LabelPlace:       "Lugar",
	LabelReason:      "Motivo",
	NoSignatures:     "El documento no tiene firmas.",

	ReportTitle:         "Informe de verificación",
	LabelDocument:       "Documento",
	LabelVerifiedAt:     "Comprobado el",
	LabelTool:           "Herramienta",
	LabelValidity:       "Certificado válido",
	LabelTrust:          "Confianza",
	LabelValidPeriod:    "Validez",
	LabelState:          "Estado",
	CertificateExpired:  "CADUCADO hace %d días",
	CertificateExpiring: "caduca en %d días",
	CertificateValid:    "válido, quedan %d días",
	LabelFindings:       "Hallazgos",
	LabelConnections:    "Conexiones",
	NoConnections:       "ninguna: comprobado sin red",
	ReportNote:          "Este informe describe lo que trebaruna comprobó y cuándo. La prueba es el documento firmado: cualquiera puede volver a comprobarlo.",

	VerdictQualified: "cualificada",
	VerdictAdvanced:  "avanzada",
	VerdictUntrusted: "emisor no reconocido",
	VerdictInvalid:   "firmante sin derecho a firmar",
	VerdictBroken:    "alterada",
	VerdictUnknown:   "indeterminada",

	StatusGood:    "correcto",
	StatusWarn:    "atención",
	StatusBad:     "error",
	StatusUnknown: "sin verificar",

	Findings: map[string]string{
		"signing_certificate.bound":              "el certificado mostrado es el que nombra la firma",
		"signing_certificate.mismatch":           "el certificado mostrado no es el que nombra la firma: la identidad que da no se firmó",
		"signing_certificate.missing":            "la firma no nombra su certificado en las propiedades firmadas: el certificado mostrado no queda vinculado a ella",
		"timestamp.archive_unbound":              "el sello de archivo no cubre esta firma como dice EN 319 132-1: no prueba nada sobre ella",
		"content.partly_signed":                  "la firma cubre solo parte del documento: estas partes no están firmadas",
		"signature.intact":                       "el contenido firmado no se ha modificado",
		"content.detached":                       "firma separada: comprobada con el documento que tiene al lado",
		"content.missing":                        "firma separada: hace falta el documento firmado para comparar sus bytes (ponlo al lado de la firma: el mismo nombre sin .p7s, o el que nombra la firma XML; o indícalo con --content)",
		"signature.unverifiable":                 "la firma usa algo que trebaruna no sabe comprobar (no es lo mismo que alterada)",
		"container.covers":                       "la firma cubre estos archivos del contenedor",
		"container.unsigned_files":               "el contenedor lleva archivos que ninguna firma cubre",
		"relationships.libxmlsec_form":           "la huella de las relaciones del paquete está calculada como lo hace libxmlsec (LibreOffice), no como dice ECMA-376: Microsoft Office puede darla por rota",
		"signature.modified":                     "el documento cambió después de firmarse",
		"certificate.trusted":                    "el emisor es una autoridad reconocida",
		"certificate.untrusted_issuer":           "el emisor no está en ninguna lista de confianza",
		"certificate.self_signed":                "certificado autofirmado: criptografía válida, sin confianza de terceros",
		"certificate.missing":                    "la firma no incluye el certificado del firmante",
		"certificate.expired_now":                "el certificado ha caducado; ya no puede crear firmas nuevas",
		"certificate.expired_at_signing":         "el certificado ya había caducado cuando se firmó",
		"certificate.not_yet_valid_at_signing":   "el certificado todavía no era válido cuando se firmó",
		"certificate.validity_unproven":          "la fecha de firma la declara el firmante y no está sellada",
		"certificate.revoked_before_signing":     "el certificado fue revocado antes de la firma",
		"certificate.revoked_after_signing":      "el certificado fue revocado después de la firma; la firma no se ve afectada",
		"certificate.revoked":                    "el certificado está revocado",
		"certificate.not_revoked":                "un respondedor confirma que el certificado no está revocado",
		"certificate.revocation_unchecked":       "no se ha podido obtener el estado de revocación del certificado",
		"timestamp.invalid":                      "el sello de tiempo existe pero no verifica",
		"timestamp.bound":                        "el sello de tiempo cubre esta firma",
		"timestamp.legacy_form":                  "el sello cubre el valor de firma tal como lo escribía trebaruna antes de 0.55.2, no su forma canónica: otros validadores no lo aceptarán",
		"timestamp.archival":                     "la firma lleva un sello de archivo (AdES-A)",
		"timestamp.accredited":                   "la autoridad de sellado es un servicio cualificado de una lista autenticada",
		"timestamp.untrusted_authority":          "el sello cubre la firma, pero su autoridad no está acreditada",
		"timestamp.not_timestamping_certificate": "el certificado del sello no tiene el uso «sellado de tiempo»",
		"trustlist.unavailable":                  "sin lista de confianza: los emisores solo se comprueban contra las raíces del sistema",
		"trustlist.stale":                        "la lista de confianza está caducada: ejecuta «trebaruna trust sync»",
		"format.unsupported":                     "no hay verificador para este formato",
		"verification.warning":                   "aviso del verificador",
		"signature.qualified":                    "firma cualificada: certificado cualificado, dispositivo cualificado y emisor cualificado vigente",
		"signature.not_qualified":                "la firma es avanzada pero no cualificada",
	},
	Issuers: map[string]string{
		"issuer.none":        "no hay certificado",
		"issuer.self_signed": "autofirmado: el certificado es su propio emisor",
		"issuer.qualified":   "prestador cualificado de la lista de confianza de %s",
		"issuer.no_roots":    "no hay raíces de confianza para validar la cadena",
		"issuer.recognised":  "el emisor es una autoridad reconocida, no cualificada",
		"issuer.unlisted":    "el emisor no está en ninguna lista de confianza",
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
	LabelPolicy:      "Politica",
	LabelRoles:       "Ruolo",
	LabelPlace:       "Luogo",
	LabelReason:      "Motivo",
	NoSignatures:     "Il documento non contiene firme.",

	ReportTitle:         "Rapporto di verifica",
	LabelDocument:       "Documento",
	LabelVerifiedAt:     "Verificato il",
	LabelTool:           "Strumento",
	LabelValidity:       "Certificato valido",
	LabelTrust:          "Affidabilità",
	LabelValidPeriod:    "Validità",
	LabelState:          "Stato",
	CertificateExpired:  "SCADUTO da %d giorni",
	CertificateExpiring: "scade tra %d giorni",
	CertificateValid:    "valido, restano %d giorni",
	LabelFindings:       "Esiti",
	LabelConnections:    "Connessioni",
	NoConnections:       "nessuna: verificato senza rete",
	ReportNote:          "Questo rapporto descrive ciò che trebaruna ha verificato e quando. La prova è il documento firmato: chiunque può verificarlo di nuovo.",

	VerdictQualified: "qualificata",
	VerdictAdvanced:  "avanzata",
	VerdictUntrusted: "emittente non riconosciuto",
	VerdictInvalid:   "firmatario non autorizzato a firmare",
	VerdictBroken:    "alterata",
	VerdictUnknown:   "indeterminata",

	StatusGood:    "corretto",
	StatusWarn:    "attenzione",
	StatusBad:     "errore",
	StatusUnknown: "non verificato",

	Findings: map[string]string{
		"signing_certificate.bound":              "il certificato mostrato è quello indicato dalla firma",
		"signing_certificate.mismatch":           "il certificato mostrato non è quello indicato dalla firma: l'identità che riporta non è stata firmata",
		"signing_certificate.missing":            "la firma non indica il suo certificato nelle proprietà firmate: il certificato mostrato non è legato a essa",
		"timestamp.archive_unbound":              "la marca di archiviazione non copre questa firma come stabilisce EN 319 132-1: non prova nulla su di essa",
		"content.partly_signed":                  "la firma copre solo una parte del documento: queste parti non sono firmate",
		"signature.intact":                       "il contenuto firmato non è stato modificato",
		"content.detached":                       "firma separata: verificata con il documento che le sta accanto",
		"content.missing":                        "firma separata: serve il documento firmato per confrontarne i byte (mettilo accanto alla firma: lo stesso nome senza .p7s, o quello che la firma XML indica; oppure indicalo con --content)",
		"signature.unverifiable":                 "la firma usa qualcosa che trebaruna non sa verificare (non vuol dire alterata)",
		"container.covers":                       "la firma copre questi file del contenitore",
		"container.unsigned_files":               "il contenitore contiene file che nessuna firma copre",
		"relationships.libxmlsec_form":           "l'impronta delle relazioni del pacchetto è calcolata come fa libxmlsec (LibreOffice), non come dice ECMA-376: Microsoft Office potrebbe considerarla non valida",
		"signature.modified":                     "il documento è cambiato dopo la firma",
		"certificate.trusted":                    "l'emittente è un'autorità riconosciuta",
		"certificate.untrusted_issuer":           "l'emittente non è in alcun elenco di fiducia",
		"certificate.self_signed":                "certificato autofirmato: crittografia valida, nessuna fiducia di terzi",
		"certificate.missing":                    "la firma non include il certificato del firmatario",
		"certificate.expired_now":                "il certificato è scaduto; non può più creare nuove firme",
		"certificate.expired_at_signing":         "il certificato era già scaduto al momento della firma",
		"certificate.not_yet_valid_at_signing":   "il certificato non era ancora valido al momento della firma",
		"certificate.validity_unproven":          "la data della firma è dichiarata dal firmatario e non è marcata",
		"certificate.revoked_before_signing":     "il certificato è stato revocato prima della firma",
		"certificate.revoked_after_signing":      "il certificato è stato revocato dopo la firma; la firma resta valida",
		"certificate.revoked":                    "il certificato è revocato",
		"certificate.not_revoked":                "un responder conferma che il certificato non è revocato",
		"certificate.revocation_unchecked":       "non è stato possibile ottenere lo stato di revoca del certificato",
		"timestamp.invalid":                      "la marca temporale esiste ma non verifica",
		"timestamp.bound":                        "la marca temporale copre questa firma",
		"timestamp.legacy_form":                  "la marca copre il valore di firma come lo scriveva trebaruna prima della 0.55.2, non la sua forma canonica: altri validatori non la accetteranno",
		"timestamp.archival":                     "la firma porta una marca di archivio (AdES-A)",
		"timestamp.accredited":                   "l'autorità di marcatura è un servizio qualificato di un elenco autenticato",
		"timestamp.untrusted_authority":          "la marca copre la firma, ma la sua autorità non è accreditata",
		"timestamp.not_timestamping_certificate": "il certificato della marca non ha l'uso «marcatura temporale»",
		"trustlist.unavailable":                  "nessun elenco di fiducia: gli emittenti sono confrontati solo con le radici di sistema",
		"trustlist.stale":                        "l'elenco di fiducia è scaduto: esegui «trebaruna trust sync»",
		"format.unsupported":                     "nessun verificatore per questo formato",
		"verification.warning":                   "avviso del verificatore",
		"signature.qualified":                    "firma qualificata: certificato qualificato, dispositivo qualificato ed emittente qualificato vigente",
		"signature.not_qualified":                "la firma è avanzata ma non qualificata",
	},
	Issuers: map[string]string{
		"issuer.none":        "nessun certificato",
		"issuer.self_signed": "autofirmato: il certificato è l'emittente di sé stesso",
		"issuer.qualified":   "prestatore qualificato dell'elenco di fiducia di %s",
		"issuer.no_roots":    "nessuna radice di fiducia per convalidare la catena",
		"issuer.recognised":  "l'emittente è un'autorità riconosciuta, non qualificata",
		"issuer.unlisted":    "l'emittente non è in alcun elenco di fiducia",
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
	LabelPolicy:      "Policy",
	LabelRoles:       "Role",
	LabelPlace:       "Place",
	LabelReason:      "Reason",
	NoSignatures:     "The document has no signatures.",

	ReportTitle:         "Verification report",
	LabelDocument:       "Document",
	LabelVerifiedAt:     "Verified on",
	LabelTool:           "Tool",
	LabelValidity:       "Certificate valid",
	LabelTrust:          "Trust",
	LabelValidPeriod:    "Validity",
	LabelState:          "State",
	CertificateExpired:  "EXPIRED %d days ago",
	CertificateExpiring: "expires in %d days",
	CertificateValid:    "valid, %d days left",
	LabelFindings:       "Findings",
	LabelConnections:    "Connections",
	NoConnections:       "none: checked offline",
	ReportNote:          "This report describes what trebaruna checked and when. The evidence is the signed document: anyone can check it again.",

	VerdictQualified: "qualified",
	VerdictAdvanced:  "advanced",
	VerdictUntrusted: "untrusted issuer",
	VerdictInvalid:   "signed without entitlement",
	VerdictBroken:    "tampered",
	VerdictUnknown:   "undetermined",

	StatusGood:    "ok",
	StatusWarn:    "warning",
	StatusBad:     "error",
	StatusUnknown: "unverified",

	Findings: map[string]string{
		"signing_certificate.bound":              "the certificate shown is the one the signature names",
		"signing_certificate.mismatch":           "the certificate shown is not the one the signature names: the identity it gives was not signed",
		"signing_certificate.missing":            "the signature names no signing certificate in its signed properties: the certificate shown is not bound to it",
		"timestamp.archive_unbound":              "the archive timestamp does not cover this signature as EN 319 132-1 reads: it proves nothing about it",
		"content.partly_signed":                  "the signature covers only part of the document: these parts are not signed",
		"signature.intact":                       "the signed content is unaltered",
		"content.detached":                       "detached signature: checked against the document beside it",
		"content.missing":                        "detached signature: the signed document is needed to compare its bytes (put it beside the signature: the same name without .p7s, or the name an XML signature gives; or name it with --content)",
		"signature.unverifiable":                 "the signature uses something trebaruna cannot check (not the same as altered)",
		"container.covers":                       "the signature covers these files of the container",
		"container.unsigned_files":               "the container holds files no signature covers",
		"relationships.libxmlsec_form":           "the package relationships are digested as libxmlsec (LibreOffice) computes them, not as ECMA-376 says: Microsoft Office may report the signature broken",
		"signature.modified":                     "the document changed after it was signed",
		"certificate.trusted":                    "the issuer is a recognised authority",
		"certificate.untrusted_issuer":           "the issuer is not in any trust list",
		"certificate.self_signed":                "self-signed certificate: valid cryptography, no third-party trust",
		"certificate.missing":                    "the signature does not embed the signing certificate",
		"certificate.expired_now":                "the certificate has expired; it can no longer create new signatures",
		"certificate.expired_at_signing":         "the certificate had already expired when the signature was made",
		"certificate.not_yet_valid_at_signing":   "the certificate was not valid yet when the signature was made",
		"certificate.validity_unproven":          "the signing time is declared by the signer and is not timestamped",
		"certificate.revoked_before_signing":     "the certificate was revoked before signing",
		"certificate.revoked_after_signing":      "the certificate was revoked after signing; the signature is unaffected",
		"certificate.revoked":                    "the certificate is revoked",
		"certificate.not_revoked":                "a responder confirmed the certificate is not revoked",
		"certificate.revocation_unchecked":       "the certificate revocation status could not be obtained",
		"timestamp.invalid":                      "the timestamp token exists but does not verify",
		"timestamp.bound":                        "the timestamp covers this signature",
		"timestamp.legacy_form":                  "the timestamp covers the signature value as trebaruna wrote it before 0.55.2, not its canonical form: other validators will not accept it",
		"timestamp.archival":                     "the signature carries an archive timestamp (AdES-A)",
		"timestamp.accredited":                   "the timestamp authority is a qualified service of an authenticated list",
		"timestamp.untrusted_authority":          "the timestamp covers the signature, but its authority is not accredited",
		"timestamp.not_timestamping_certificate": "the timestamp certificate lacks the time-stamping key usage",
		"trustlist.unavailable":                  "no trust list: issuers are checked against the system roots only",
		"trustlist.stale":                        "the trust list is out of date: run 'trebaruna trust sync'",
		"format.unsupported":                     "no verifier is available for this format",
		"verification.warning":                   "verifier warning",
		"signature.qualified":                    "qualified signature: qualified certificate, qualified device and a currently granted qualified issuer",
		"signature.not_qualified":                "the signature is advanced but not qualified",
	},
	Issuers: map[string]string{
		"issuer.none":        "no certificate",
		"issuer.self_signed": "self-signed: the certificate is its own issuer",
		"issuer.qualified":   "qualified provider in the %s trusted list",
		"issuer.no_roots":    "no trusted roots to validate the chain",
		"issuer.recognised":  "the issuer is a recognised authority, not a qualified one",
		"issuer.unlisted":    "the issuer is not in any trust list",
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
	case domain.TrustInvalid:
		return c.VerdictInvalid
	case domain.TrustBroken:
		return c.VerdictBroken
	}
	return c.VerdictUnknown
}

// DeclarationRows are the label and value of each thing a signature
// declares of itself, for a report.
func (c Catalogue) DeclarationRows(declared domain.Declarations) [][2]string {
	var rows [][2]string
	if declared.Policy != "" {
		rows = append(rows, [2]string{c.LabelPolicy, declared.PolicyText()})
	}
	if len(declared.Roles) > 0 {
		rows = append(rows, [2]string{c.LabelRoles, strings.Join(declared.Roles, ", ")})
	}
	if declared.Place != "" {
		rows = append(rows, [2]string{c.LabelPlace, declared.Place})
	}
	if declared.Reason != "" {
		rows = append(rows, [2]string{c.LabelReason, declared.Reason})
	}
	return rows
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

// IssuerNote says why a certificate's issuer is trusted or not, from the
// trust verdict's code; the qualified one names the list's territory. The
// verdict's English reason is the fallback for a code not here.
func (c Catalogue) IssuerNote(code, territory, fallback string) string {
	note, ok := c.Issuers[code]
	if !ok {
		return fallback
	}
	if strings.Contains(note, "%s") {
		return fmt.Sprintf(note, territory)
	}
	return note
}

// issuerCodes are the trust verdict's codes every language explains.
var issuerCodes = []string{"issuer.none", "issuer.self_signed", "issuer.qualified", "issuer.no_roots", "issuer.recognised", "issuer.unlisted"}

// compile-time guard: every language must define every finding code.
func init() {
	required := []string{
		"signature.intact", "signature.modified", "certificate.trusted",
		"certificate.untrusted_issuer", "certificate.self_signed", "certificate.missing",
		"certificate.expired_now", "certificate.expired_at_signing",
		"certificate.not_yet_valid_at_signing", "certificate.validity_unproven",
		"certificate.revoked_before_signing", "certificate.revoked_after_signing",
		"certificate.revoked", "certificate.not_revoked",
		"certificate.revocation_unchecked",
		"timestamp.invalid", "timestamp.bound", "timestamp.archival",
		"timestamp.accredited", "timestamp.untrusted_authority",
		"timestamp.not_timestamping_certificate", "trustlist.unavailable",
		"trustlist.stale", "format.unsupported", "verification.warning",
		"signature.qualified", "signature.not_qualified",
		"signature.unverifiable", "container.covers", "container.unsigned_files", "relationships.libxmlsec_form", "timestamp.legacy_form",
		"signing_certificate.bound", "signing_certificate.mismatch", "signing_certificate.missing", "timestamp.archive_unbound", "content.partly_signed",
	}

	for name, catalogue := range languages {
		for _, code := range required {
			if _, ok := catalogue.Findings[code]; !ok {
				panic(fmt.Sprintf("catalogue %s is missing the finding %q", name, code))
			}
		}
		for _, code := range issuerCodes {
			if _, ok := catalogue.Issuers[code]; !ok {
				panic(fmt.Sprintf("catalogue %s is missing the issuer note %q", name, code))
			}
		}
	}
}

// languages are the report's catalogues by language tag.
var languages = map[string]Catalogue{
	"es": Spanish, "ca": Catalan, "gl": Galician, "eu": Basque, "it": Italian, "pl": Polish, "en": English,
}

// Tag is the language a locale string names ("it", "ca_ES.UTF-8"), among
// the report's; "es" when none matches.
func Tag(locale string) string {
	if len(locale) < 2 {
		return "es"
	}
	tag := strings.ToLower(locale[:2])
	if _, known := languages[tag]; !known {
		return "es"
	}
	return tag
}

// For picks the catalogue of the language a locale string names; Spanish
// when none matches.
func For(locale string) Catalogue { return languages[Tag(locale)] }
