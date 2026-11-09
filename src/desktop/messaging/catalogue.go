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
	RequestsTab            string
	Approve                string
	Reject                 string
	ApprovalSecret         string
	DecisionRecorded       string
	NoPendingRequests      string
	PendingRequests        string
	ExpiresIn              string
	NoBinary               string
	VerifySection          string
	VerifyHint             string
	VerifyButton           string
	VerificationUnreadable string

	// The page pane, where the seal is placed.
	SuggestButton    string
	NoPreviewYet     string
	NoVisibleSeal    string
	RenderingMessage string
	// PreviewUnavailable explains a missing renderer without blocking signing.
	PreviewUnavailable    string
	PageOf                string
	SealHint              string
	SealCoversText        string
	SealHolderPlaceholder string
	NoSuggestion          string
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
	Language:               Spanish,
	VerifySection:          "Comprobar una firma",
	VerifyHint:             "Elige o arrastra un documento firmado: PDF, .p7m, .p7s o XML. Se comprueba sin conexión contra las listas de confianza europeas.",
	VerifyButton:           "Comprobar",
	VerificationUnreadable: "No se pudo leer el informe de verificación.",
	SignTab:                "Firma",
	VerifyTab:              "Verificar",
	RequestsTab:            "Peticiones",
	Approve:                "Aprobar",
	Reject:                 "Rechazar",
	ApprovalSecret:         "Secreto de aprobación",
	DecisionRecorded:       "Decisión registrada",
	NoPendingRequests:      "No hay peticiones pendientes",
	PendingRequests:        "Peticiones pendientes: %d",
	ExpiresIn:              "Caduca en",
	NoBinary:               "No se encontró el binario trebaruna",
	WindowTitle:            "trebaruna — firma electrónica AdES",
	Subtitle:               "CAdES · PAdES · XAdES — sin código propietario",
	DocumentLabel:          "Documento",
	CertificateLabel:       "Certificado (.p12 / .pfx / .pem)",
	PassphraseLabel:        "Contraseña",
	FormatLabel:            "Formato",
	LevelLabel:             "Nivel",
	CaptionLabel:           "Texto del sello",
	TSALabel:               "Autoridad de sellado (TSA)",
	ReasonLabel:            "Motivo",
	LocationLabel:          "Lugar",
	ResultLabel:            "Resultado",
	ChooseButton:           "Elegir…",
	SignButton:             "Firmar",
	SigningMessage:         "firmando…",
	DoneTitle:              "Firma completada",
	DoneQuestion:           "Documento firmado:\n%s\n\n¿Abrirlo?",
	MissingDocument:        "Elige un documento para firmar.",
	MissingKey:             "Elige tu certificado (.p12, .pfx o .pem).",
	MissingTSA:             "El nivel %s necesita una autoridad de sellado (TSA).",
	InvalidPage:            "La página del sello empieza en 1.",
	NoOutput:               "La firma no produjo %s.",
	SelectOnePlaceholder:   "(elige uno)",

	WelcomeTitle:   "trebaruna",
	WelcomeTagline: "Firma electrónica CAdES, PAdES y XAdES.\nSin Electron, sin Java, sin código propietario.",
	WelcomePoint1:  "· El sello se rellena con los datos de tu certificado.",
	WelcomePoint2:  "· Arrastra el sello a cualquier hueco de la página.",
	WelcomePoint3:  "· Funciona sin conexión; solo la TSA usa la red.",
	WelcomeStart:   "Empezar",

	DocumentSection: "Documento y certificado",
	OptionsSection:  "Formato y sello de tiempo",
	SealSection:     "Sello visible",

	SuggestButton:         "Buscar hueco libre",
	NoPreviewYet:          "Elige un PDF para ver la página y colocar el sello.",
	NoVisibleSeal:         "Este formato no lleva sello visible: la firma viaja en el fichero .p7m o dentro del XML.",
	RenderingMessage:      "Preparando la página…",
	PreviewUnavailable:    "No se puede mostrar la página porque falta poppler (pdftoppm). La firma funciona igual: el sello irá en la esquina inferior derecha de la página 1.",
	PageOf:                "Página %d de %d",
	SealHint:              "Haz clic en la página para colocar el sello, arrástralo para moverlo y tira de la esquina para ampliarlo. Con el teclado, las flechas lo desplazan.",
	SealCoversText:        "El sello tapa texto del documento. Muévelo a un hueco o pulsa «Buscar hueco libre».",
	SealHolderPlaceholder: "Titular del certificado",
	NoSuggestion:          "No hay otro hueco libre en esta página: coloca el sello a mano o cambia de página.",
}

var italian = Catalogue{
	Language:               Italian,
	VerifySection:          "Verifica una firma",
	VerifyHint:             "Scegli o trascina un documento firmato: PDF, .p7m, .p7s o XML. La verifica avviene offline sulle liste di fiducia europee.",
	VerifyButton:           "Verifica",
	VerificationUnreadable: "Impossibile leggere il rapporto di verifica.",
	SignTab:                "Firma",
	VerifyTab:              "Verifica",
	RequestsTab:            "Richieste",
	Approve:                "Approva",
	Reject:                 "Rifiuta",
	ApprovalSecret:         "Segreto di approvazione",
	DecisionRecorded:       "Decisione registrata",
	NoPendingRequests:      "Nessuna richiesta in attesa",
	PendingRequests:        "Richieste in attesa: %d",
	ExpiresIn:              "Scade tra",
	NoBinary:               "Binario trebaruna non trovato",
	WindowTitle:            "trebaruna — firma elettronica AdES",
	Subtitle:               "CAdES · PAdES · XAdES — senza codice proprietario",
	DocumentLabel:          "Documento",
	CertificateLabel:       "Certificato (.p12 / .pfx / .pem)",
	PassphraseLabel:        "Password",
	FormatLabel:            "Formato",
	LevelLabel:             "Livello",
	CaptionLabel:           "Testo del timbro",
	TSALabel:               "Autorità di marca temporale (TSA)",
	ReasonLabel:            "Motivo",
	LocationLabel:          "Luogo",
	ResultLabel:            "Risultato",
	ChooseButton:           "Scegli…",
	SignButton:             "Firma",
	SigningMessage:         "firma in corso…",
	DoneTitle:              "Firma completata",
	DoneQuestion:           "Documento firmato:\n%s\n\nVuoi aprirlo?",
	MissingDocument:        "Scegli un documento da firmare.",
	MissingKey:             "Scegli il tuo certificato (.p12, .pfx o .pem).",
	MissingTSA:             "Il livello %s richiede un'autorità di marca temporale (TSA).",
	InvalidPage:            "La pagina del timbro parte da 1.",
	NoOutput:               "La firma non ha prodotto %s.",
	SelectOnePlaceholder:   "(scegli)",

	WelcomeTitle:   "trebaruna",
	WelcomeTagline: "Firma elettronica CAdES, PAdES e XAdES.\nSenza Electron, senza Java, senza codice proprietario.",
	WelcomePoint1:  "· Il timbro riporta i dati del tuo certificato.",
	WelcomePoint2:  "· Trascina il timbro in qualsiasi spazio della pagina.",
	WelcomePoint3:  "· Funziona offline; solo la TSA usa la rete.",
	WelcomeStart:   "Inizia",

	DocumentSection: "Documento e certificato",
	OptionsSection:  "Formato e marca temporale",
	SealSection:     "Timbro visibile",

	SuggestButton:         "Trova uno spazio libero",
	NoPreviewYet:          "Scegli un PDF per vedere la pagina e posizionare il timbro.",
	NoVisibleSeal:         "Questo formato non ha un timbro visibile: la firma è nel file .p7m o dentro l'XML.",
	RenderingMessage:      "Preparazione della pagina…",
	PreviewUnavailable:    "Impossibile mostrare la pagina: manca poppler (pdftoppm). La firma funziona comunque: il timbro andrà nell'angolo in basso a destra della pagina 1.",
	PageOf:                "Pagina %d di %d",
	SealHint:              "Fai clic sulla pagina per posizionare il timbro, trascinalo per spostarlo e tira l'angolo per ingrandirlo. Da tastiera, le frecce lo spostano.",
	SealCoversText:        "Il timbro copre del testo. Spostalo in uno spazio vuoto o premi «Trova uno spazio libero».",
	SealHolderPlaceholder: "Titolare del certificato",
	NoSuggestion:          "Nessun altro spazio libero in questa pagina: posiziona il timbro a mano o cambia pagina.",
}

var english = Catalogue{
	Language:               English,
	VerifySection:          "Check a signature",
	VerifyHint:             "Choose or drop a signed document: PDF, .p7m, .p7s or XML. It is checked offline against the European trust lists.",
	VerifyButton:           "Check",
	VerificationUnreadable: "The verification report could not be read.",
	SignTab:                "Sign",
	VerifyTab:              "Verify",
	RequestsTab:            "Requests",
	Approve:                "Approve",
	Reject:                 "Reject",
	ApprovalSecret:         "Approval secret",
	DecisionRecorded:       "Decision recorded",
	NoPendingRequests:      "No pending requests",
	PendingRequests:        "Pending requests: %d",
	ExpiresIn:              "Expires in",
	NoBinary:               "The trebaruna binary was not found",
	WindowTitle:            "trebaruna — AdES electronic signature",
	Subtitle:               "CAdES · PAdES · XAdES — no proprietary code",
	DocumentLabel:          "Document",
	CertificateLabel:       "Certificate (.p12 / .pfx / .pem)",
	PassphraseLabel:        "Passphrase",
	FormatLabel:            "Format",
	LevelLabel:             "Level",
	CaptionLabel:           "Seal caption",
	TSALabel:               "Timestamp authority (TSA)",
	ReasonLabel:            "Reason",
	LocationLabel:          "Location",
	ResultLabel:            "Result",
	ChooseButton:           "Choose…",
	SignButton:             "Sign",
	SigningMessage:         "signing…",
	DoneTitle:              "Signature completed",
	DoneQuestion:           "Signed document:\n%s\n\nOpen it?",
	MissingDocument:        "Choose a document to sign.",
	MissingKey:             "Choose your certificate (.p12, .pfx or .pem).",
	MissingTSA:             "Level %s needs a timestamp authority (TSA).",
	InvalidPage:            "Seal pages start at 1.",
	NoOutput:               "The signature did not produce %s.",
	SelectOnePlaceholder:   "(select one)",

	WelcomeTitle:   "trebaruna",
	WelcomeTagline: "CAdES, PAdES and XAdES electronic signatures.\nNo Electron, no Java, no proprietary code.",
	WelcomePoint1:  "· The seal is filled from your certificate.",
	WelcomePoint2:  "· Drag the seal anywhere on the page.",
	WelcomePoint3:  "· Works offline; only the TSA uses the network.",
	WelcomeStart:   "Start",

	DocumentSection: "Document and certificate",
	OptionsSection:  "Format and timestamp",
	SealSection:     "Visible seal",

	SuggestButton:         "Find free space",
	NoPreviewYet:          "Choose a PDF to see the page and place the seal.",
	NoVisibleSeal:         "This format has no visible seal: the signature travels in the .p7m file or inside the XML.",
	RenderingMessage:      "Preparing the page…",
	PreviewUnavailable:    "The page cannot be shown because poppler (pdftoppm) is missing. Signing still works: the seal goes in the bottom-right corner of page 1.",
	PageOf:                "Page %d of %d",
	SealHint:              "Click the page to place the seal, drag it to move it and pull its corner to enlarge it. With the keyboard, the arrow keys nudge it.",
	SealCoversText:        "The seal covers text in the document. Move it to an empty area or press \"Find free space\".",
	SealHolderPlaceholder: "Certificate holder",
	NoSuggestion:          "No other free space on this page: place the seal by hand or change page.",
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
