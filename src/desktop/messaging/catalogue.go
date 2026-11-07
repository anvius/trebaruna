// Package messaging holds every user-visible string, in the user's language.
//
// Two hard rules, both learned from watching people use signing tools:
//   - no string is hardcoded in a window or a command;
//   - a missing translation is a compile error, not a silent English fallback.
package messaging

import "fmt"

// Language is a supported interface language.
type Language string

const (
	// Spanish is the default: the author reads Spanish.
	Spanish Language = "es"

	// Italian is required because the documents are Italian.
	Italian Language = "it"

	// English is the fallback for bug reports and foreign colleagues.
	English Language = "en"
)

// ParseLanguage maps a locale name onto a supported language.
//
// It accepts "it", "it-IT", "es_ES" and similar, so the value can come straight
// from LANG without normalisation at the call site.
func ParseLanguage(raw string) Language {
	if len(raw) < 2 {
		return Spanish
	}
	switch raw[:2] {
	case "it":
		return Italian
	case "en":
		return English
	case "es":
		return Spanish
	}
	return Spanish
}

// Catalogue is the set of strings for one language.
type Catalogue struct {
	Language Language

	WindowTitle          string
	Subtitle             string
	DocumentLabel        string
	CertificateLabel     string
	PassphraseLabel      string
	FormatLabel          string
	LevelLabel           string
	PageLabel            string
	BoxLabel             string
	CaptionLabel         string
	TSALabel             string
	ReasonLabel          string
	LocationLabel        string
	ResultLabel          string
	ChooseButton         string
	SignButton           string
	SigningMessage       string
	DoneTitle            string
	DoneQuestion         string
	MissingDocument      string
	MissingKey           string
	MissingTSA           string
	InvalidPage          string
	NoOutput             string
	SelectOnePlaceholder string

	// Welcome screen.
	WelcomeTitle   string
	WelcomeTagline string
	WelcomePoint1  string
	WelcomePoint2  string
	WelcomePoint3  string
	WelcomeStart   string

	// Sections of the two-pane window.
	DocumentSection string
	OptionsSection  string
	SealSection     string

	// Verification tab.
	VerifyTab              string
	SignTab                string
	VerifySection          string
	VerifyHint             string
	VerifyButton           string
	VerificationUnreadable string

	// Preview and free-space messages.
	PreviewButton     string
	SuggestButton     string
	NoPreviewYet      string
	PreviewOnlyForPDF string
	RenderingMessage  string
	// PreviewUnavailable explains a missing renderer without blocking signing.
	PreviewUnavailable string
	PreviewReady       string
	NoSuggestion       string
	SuggestionApplied  string
}

// For returns the catalogue for a language.
func For(language Language) Catalogue {
	switch language {
	case Italian:
		return italian
	case English:
		return english
	default:
		return spanish
	}
}

var spanish = Catalogue{
	Language:             Spanish,
	WindowTitle:          "firma-it — firma electrónica AdES",
	Subtitle:             "CAdES · PAdES · XAdES — sin código propietario",
	DocumentLabel:        "Documento",
	CertificateLabel:     "Certificado (.p12 / .pfx / .pem)",
	PassphraseLabel:      "Contraseña",
	FormatLabel:          "Formato",
	LevelLabel:           "Nivel",
	PageLabel:            "Página del sello",
	BoxLabel:             "Hueco (x1,y1,x2,y2)",
	CaptionLabel:         "Texto del sello",
	TSALabel:             "Autoridad de sellado (TSA)",
	ReasonLabel:          "Motivo",
	LocationLabel:        "Lugar",
	ResultLabel:          "Resultado",
	ChooseButton:         "Elegir…",
	SignButton:           "Firmar",
	SigningMessage:       "firmando…",
	DoneTitle:            "Firma completada",
	DoneQuestion:         "Documento firmado:\n%s\n\n¿Abrirlo?",
	MissingDocument:      "Elige un documento para firmar.",
	MissingKey:           "Elige tu certificado (.p12, .pfx o .pem).",
	MissingTSA:           "El nivel %s necesita una autoridad de sellado (TSA).",
	InvalidPage:          "La página del sello empieza en 1.",
	NoOutput:             "La firma no produjo %s.",
	SelectOnePlaceholder: "(elige uno)",

	WelcomeTitle:   "firma-it",
	WelcomeTagline: "Firma electrónica CAdES, PAdES y XAdES.\nSin Electron, sin Java, sin código propietario.",
	WelcomePoint1:  "· El sello se rellena con los datos de tu certificado.",
	WelcomePoint2:  "· Arrastra el sello a cualquier hueco de la página.",
	WelcomePoint3:  "· Funciona sin conexión; solo la TSA usa la red.",
	WelcomeStart:   "Empezar",

	DocumentSection: "Documento y certificado",
	OptionsSection:  "Formato y sello de tiempo",
	SealSection:     "Sello visible",

	PreviewButton:      "Ver página",
	SuggestButton:      "Sugerir hueco",
	NoPreviewYet:       "Elige un PDF y pulsa «Ver página»\npara verlo y arrastrar el sello.",
	PreviewOnlyForPDF:  "La vista previa solo está disponible para PAdES (PDF).",
	RenderingMessage:   "Renderizando la página…",
	PreviewUnavailable: "Vista previa no disponible: falta poppler.\nPuedes firmar igualmente indicando el hueco a mano.",
	PreviewReady:       "Documento de %d páginas · mostrando la %d · hueco propuesto: %s",
	NoSuggestion:       "No encontré otro hueco: coloca el sello manualmente.",
	SuggestionApplied:  "Hueco aplicado. Arrástralo con el ratón para ajustarlo.",
}

var italian = Catalogue{
	Language:             Italian,
	WindowTitle:          "firma-it — firma elettronica AdES",
	Subtitle:             "CAdES · PAdES · XAdES — senza codice proprietario",
	DocumentLabel:        "Documento",
	CertificateLabel:     "Certificato (.p12 / .pfx / .pem)",
	PassphraseLabel:      "Password",
	FormatLabel:          "Formato",
	LevelLabel:           "Livello",
	PageLabel:            "Pagina del timbro",
	BoxLabel:             "Riquadro (x1,y1,x2,y2)",
	CaptionLabel:         "Testo del timbro",
	TSALabel:             "Autorità di marca temporale (TSA)",
	ReasonLabel:          "Motivo",
	LocationLabel:        "Luogo",
	ResultLabel:          "Risultato",
	ChooseButton:         "Scegli…",
	SignButton:           "Firma",
	SigningMessage:       "firma in corso…",
	DoneTitle:            "Firma completata",
	DoneQuestion:         "Documento firmato:\n%s\n\nVuoi aprirlo?",
	MissingDocument:      "Scegli un documento da firmare.",
	MissingKey:           "Scegli il tuo certificato (.p12, .pfx o .pem).",
	MissingTSA:           "Il livello %s richiede un'autorità di marca temporale (TSA).",
	InvalidPage:          "La pagina del timbro parte da 1.",
	NoOutput:             "La firma non ha prodotto %s.",
	SelectOnePlaceholder: "(scegli)",

	WelcomeTitle:   "firma-it",
	WelcomeTagline: "Firma elettronica CAdES, PAdES e XAdES.\nSenza Electron, senza Java, senza codice proprietario.",
	WelcomePoint1:  "· Il timbro riporta i dati del tuo certificato.",
	WelcomePoint2:  "· Trascina il timbro in qualsiasi spazio della pagina.",
	WelcomePoint3:  "· Funziona offline; solo la TSA usa la rete.",
	WelcomeStart:   "Inizia",

	DocumentSection: "Documento e certificato",
	OptionsSection:  "Formato e marca temporale",
	SealSection:     "Timbro visibile",

	PreviewButton:      "Mostra pagina",
	SuggestButton:      "Suggerisci spazio",
	NoPreviewYet:       "Scegli un PDF e premi «Mostra pagina»\nper vederlo e trascinare il timbro.",
	PreviewOnlyForPDF:  "L'anteprima è disponibile solo per PAdES (PDF).",
	RenderingMessage:   "Rendering della pagina…",
	PreviewUnavailable: "Anteprima non disponibile: manca poppler.\nPuoi firmare comunque indicando il riquadro a mano.",
	PreviewReady:       "Documento di %d pagine · pagina %d · spazio proposto: %s",
	NoSuggestion:       "Nessun altro spazio trovato: posiziona il timbro a mano.",
	SuggestionApplied:  "Spazio applicato. Trascinalo col mouse per regolarlo.",
}

var english = Catalogue{
	Language:             English,
	WindowTitle:          "firma-it — AdES electronic signature",
	Subtitle:             "CAdES · PAdES · XAdES — no proprietary code",
	DocumentLabel:        "Document",
	CertificateLabel:     "Certificate (.p12 / .pfx / .pem)",
	PassphraseLabel:      "Passphrase",
	FormatLabel:          "Format",
	LevelLabel:           "Level",
	PageLabel:            "Seal page",
	BoxLabel:             "Box (x1,y1,x2,y2)",
	CaptionLabel:         "Seal caption",
	TSALabel:             "Timestamp authority (TSA)",
	ReasonLabel:          "Reason",
	LocationLabel:        "Location",
	ResultLabel:          "Result",
	ChooseButton:         "Choose…",
	SignButton:           "Sign",
	SigningMessage:       "signing…",
	DoneTitle:            "Signature completed",
	DoneQuestion:         "Signed document:\n%s\n\nOpen it?",
	MissingDocument:      "Choose a document to sign.",
	MissingKey:           "Choose your certificate (.p12, .pfx or .pem).",
	MissingTSA:           "Level %s needs a timestamp authority (TSA).",
	InvalidPage:          "Seal pages start at 1.",
	NoOutput:             "The signature did not produce %s.",
	SelectOnePlaceholder: "(select one)",

	WelcomeTitle:   "firma-it",
	WelcomeTagline: "CAdES, PAdES and XAdES electronic signatures.\nNo Electron, no Java, no proprietary code.",
	WelcomePoint1:  "· The seal is filled from your certificate.",
	WelcomePoint2:  "· Drag the seal anywhere on the page.",
	WelcomePoint3:  "· Works offline; only the TSA uses the network.",
	WelcomeStart:   "Start",

	DocumentSection: "Document and certificate",
	OptionsSection:  "Format and timestamp",
	SealSection:     "Visible seal",

	PreviewButton:      "Show page",
	SuggestButton:      "Suggest space",
	NoPreviewYet:       "Choose a PDF and press \"Show page\"\nto see it and drag the seal.",
	PreviewOnlyForPDF:  "Preview is only available for PAdES (PDF).",
	RenderingMessage:   "Rendering the page…",
	PreviewUnavailable: "Preview unavailable: poppler is missing.\nYou can still sign by entering the box manually.",
	PreviewReady:       "%d-page document · showing %d · suggested space: %s",
	NoSuggestion:       "No other space found: place the seal manually.",
	SuggestionApplied:  "Space applied. Drag it with the mouse to adjust.",
}

// LevelName renders a level name for display.
func (c Catalogue) LevelNameFor(level string) string {
	switch level {
	case "bes":
		return "BES"
	case "t":
		return "T"
	case "lt":
		return "LT"
	case "lta":
		return "LTA"
	}
	return level
}

// MissingTSAMessage formats the missing-authority error.
func (c Catalogue) MissingTSAMessage(level string) string {
	return fmt.Sprintf(c.MissingTSA, c.LevelNameFor(level))
}

// DoneMessage formats the success question.
func (c Catalogue) DoneMessage(path string) string {
	return fmt.Sprintf(c.DoneQuestion, path)
}

// NoOutputMessage formats the missing-artefact error.
func (c Catalogue) NoOutputMessage(path string) string {
	return fmt.Sprintf(c.NoOutput, path)
}
