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

	WindowTitle     string
	LevelLabel      string
	TSALabel        string
	ReasonLabel     string
	LocationLabel   string
	ChooseButton    string
	SignButton      string
	SigningMessage  string
	MissingDocument string
	MissingKey      string
	MissingTSA      string
	InvalidPage     string
	NoOutput        string

	// Welcome screen.
	WelcomeTitle   string
	WelcomeTagline string
	WelcomePoint1  string
	WelcomePoint2  string
	WelcomePoint3  string
	WelcomeStart   string

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

	// The signing form.
	StepDocument               string
	StepCertificate            string
	StepSignature              string
	ChooseDocument             string
	ChooseCertificate          string
	ChangeButton               string
	DropHint                   string
	CertificateHint            string
	DocumentSavedAs            string
	PassphrasePlaceholder      string
	CertificateReading         string
	CertificateNeedsPassphrase string
	CertificateLocked          string
	IssuedBy                   string
	ValidUntil                 string
	StandingQualified          string
	StandingTrusted            string
	StandingUntrusted          string
	StandingExpired            string
	CertificateExpiresSoon     string
	FormatPAdESLabel           string
	FormatCAdESLabel           string
	FormatXAdESLabel           string
	FormatOnlyCAdES            string
	SealOnPagePane             string
	MoreOptions                string
	LevelBasicLabel            string
	LevelTimestampLabel        string
	LevelLongTermLabel         string
	LevelArchiveLabel          string
	LevelHint                  string
	LocationPlaceholder        string
	SignedAs                   string
	OpenSigned                 string
	ShowFolder                 string
	CheckSignature             string
	TSAUserLabel               string
	TSAPasswordLabel           string
	TSAAccountHint             string

	// Menus and dialogs.
	MenuFile              string
	MenuOpenDocument      string
	MenuChooseCertificate string
	MenuCheckDocument     string
	MenuSignature         string
	MenuPreviousPage      string
	MenuNextPage          string
	MenuTools             string
	MenuRequests          string
	MenuHelp              string
	MenuManual            string
	MenuAbout             string
	AboutText             string
	UnknownVersion        string
	CloseButton           string
	RefreshButton         string

	// Verification results in plain words.
	OnlineRevocation string
	CheckingMessage  string
	ExplainQualified string
	ExplainAdvanced  string
	ExplainUntrusted string
	ExplainInvalid   string
	ExplainBroken    string
	ExplainUnknown   string

	// Network activity (ADR-0010).
	MenuNetwork          string
	NetworkTitle         string
	NetworkEmpty         string
	NetworkSummary       string
	NetworkBytes         string
	NetworkViaLibrary    string
	PurposeTimestamp     string
	PurposeRevocation    string
	PurposeTrustList     string
	PurposeWebDelivery   string
	PurposeLocalAPI      string
	PurposeSigningServer string
	PurposeRemoteSigning string
	PurposeUnattributed  string
	DocumentFingerprint  string
	DocumentChanged      string
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
	SignTab:                "Firmar",
	VerifyTab:              "Comprobar",
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
	LevelLabel:             "Nivel",
	TSALabel:               "Autoridad de sellado (TSA)",
	ReasonLabel:            "Motivo",
	LocationLabel:          "Lugar",
	ChooseButton:           "Elegir…",
	SignButton:             "Firmar",
	SigningMessage:         "firmando…",
	MissingDocument:        "Elige un documento para firmar.",
	MissingKey:             "Elige tu certificado (.p12, .pfx o .pem).",
	MissingTSA:             "El nivel %s necesita una autoridad de sellado (TSA).",
	InvalidPage:            "La página del sello empieza en 1.",
	NoOutput:               "La firma no produjo %s.",

	WelcomeTitle:   "trebaruna",
	WelcomeTagline: "Firma electrónica CAdES, PAdES y XAdES.\nSin Electron, sin Java, sin código propietario.",
	WelcomePoint1:  "· El sello se rellena con los datos de tu certificado.",
	WelcomePoint2:  "· Arrastra el sello a cualquier hueco de la página.",
	WelcomePoint3:  "· Funciona sin conexión; solo la TSA usa la red.",
	WelcomeStart:   "Empezar",

	SuggestButton:              "Buscar hueco libre",
	NoPreviewYet:               "Elige un PDF para ver la página y colocar el sello.",
	NoVisibleSeal:              "Este formato no lleva sello visible: la firma viaja en el fichero .p7m o dentro del XML.",
	RenderingMessage:           "Preparando la página…",
	PreviewUnavailable:         "No se puede mostrar la página porque falta poppler (pdftoppm). La firma funciona igual: el sello irá en la esquina inferior derecha de la página 1.",
	PageOf:                     "Página %d de %d",
	SealHint:                   "Haz clic en la página para colocar el sello, arrástralo para moverlo y tira de la esquina para ampliarlo. Con el teclado, las flechas lo desplazan.",
	SealCoversText:             "El sello tapa texto del documento. Muévelo a un hueco o pulsa «Buscar hueco libre».",
	SealHolderPlaceholder:      "Titular del certificado",
	NoSuggestion:               "No hay otro hueco libre en esta página: coloca el sello a mano o cambia de página.",
	StepDocument:               "Documento",
	StepCertificate:            "Certificado",
	StepSignature:              "Firma",
	ChooseDocument:             "Elegir documento…",
	ChooseCertificate:          "Elegir certificado…",
	ChangeButton:               "Cambiar…",
	DropHint:                   "PDF, XML o cualquier otro fichero. También puedes arrastrarlo a la ventana.",
	CertificateHint:            "Fichero .p12, .pfx o .pem con tu certificado y su clave.",
	DocumentSavedAs:            "Se guardará como %s",
	PassphrasePlaceholder:      "Contraseña del certificado",
	CertificateReading:         "Leyendo el certificado…",
	CertificateNeedsPassphrase: "Escribe la contraseña para leer el certificado.",
	CertificateLocked:          "La contraseña no abre este certificado.",
	IssuedBy:                   "Emitido por %s",
	ValidUntil:                 "Válido hasta el %s",
	StandingQualified:          "Certificado cualificado: la firma tiene plena validez legal (eIDAS).",
	StandingTrusted:            "Emisor de confianza: firma avanzada, aunque el certificado no es cualificado.",
	StandingUntrusted:          "Ninguna lista de confianza respalda a este emisor: la firma será técnicamente correcta, pero sin respaldo legal.",
	StandingExpired:            "Caducó el %s: ya no sirve para firmar.",
	CertificateExpiresSoon:     "Caduca en %d días.",
	FormatPAdESLabel:           "PDF firmado (PAdES): se abre en cualquier lector",
	FormatCAdESLabel:           "Sobre .p7m (CAdES): el que piden algunas administraciones",
	FormatXAdESLabel:           "XML firmado (XAdES)",
	FormatOnlyCAdES:            "Este tipo de fichero se firma dentro de un sobre .p7m (CAdES).",
	SealOnPagePane:             "El sello irá donde lo ves en la página de la derecha.",
	MoreOptions:                "Más opciones",
	LevelBasicLabel:            "Básica, sin sello de tiempo",
	LevelTimestampLabel:        "Con sello de tiempo (T)",
	LevelLongTermLabel:         "Validación a largo plazo (LT)",
	LevelArchiveLabel:          "Archivo a largo plazo (LTA)",
	LevelHint:                  "El sello de tiempo prueba cuándo se firmó. LT y LTA consultan además por red si el certificado estaba revocado.",
	LocationPlaceholder:        "Ciudad",
	SignedAs:                   "Firmado: %s",
	OpenSigned:                 "Abrir",
	ShowFolder:                 "Carpeta",
	CheckSignature:             "Comprobar",
	TSAUserLabel:               "Usuario de la TSA (si la autoridad lo pide)",
	TSAPasswordLabel:           "Contraseña de la TSA",
	TSAAccountHint:             "Algunas autoridades, como las de Aruba o InfoCert, solo sellan con una cuenta. El usuario se recuerda; la contraseña, no.",
	MenuFile:                   "Archivo",
	MenuOpenDocument:           "Abrir documento para firmar…",
	MenuChooseCertificate:      "Elegir certificado…",
	MenuCheckDocument:          "Comprobar un documento firmado…",
	MenuSignature:              "Firma",
	MenuPreviousPage:           "Página anterior",
	MenuNextPage:               "Página siguiente",
	MenuTools:                  "Herramientas",
	MenuRequests:               "Peticiones de páginas web…",
	MenuHelp:                   "Ayuda",
	MenuManual:                 "Manual",
	MenuAbout:                  "Acerca de trebaruna",
	AboutText:                  "Firma electrónica CAdES, PAdES y XAdES sin código propietario.\nVersión %s\nLicencia AGPL-3.0-or-later.",
	UnknownVersion:             "desconocida (no se encontró el programa trebaruna)",
	CloseButton:                "Cerrar",
	RefreshButton:              "Actualizar",
	OnlineRevocation:           "Consultar por red si el certificado estaba revocado (OCSP)",
	CheckingMessage:            "Comprobando…",
	ExplainQualified:           "El documento no ha cambiado y la firma es cualificada: equivale a una firma manuscrita en toda la Unión Europea.",
	ExplainAdvanced:            "El documento no ha cambiado y una lista de confianza europea respalda al emisor del certificado.",
	ExplainUntrusted:           "El documento no ha cambiado, pero ninguna lista de confianza respalda al emisor del certificado.",
	ExplainInvalid:             "El documento no ha cambiado, pero el certificado no servía para firmar en ese momento: estaba caducado o revocado.",
	ExplainBroken:              "El documento cambió después de firmarse: la firma ya no corresponde a su contenido.",
	ExplainUnknown:             "Con la información disponible no se puede decidir si la firma es válida.",
	MenuNetwork:                "Actividad de red…",
	NetworkTitle:               "Actividad de red de esta sesión",
	NetworkEmpty:               "En esta sesión no se ha hecho ninguna conexión. Firmar en nivel básico y comprobar sin consultar la revocación no usan la red.",
	NetworkSummary:             "Conexiones: %s",
	NetworkBytes:               "%s enviados, %s recibidos",
	NetworkViaLibrary:          "Abierta por una librería de terceros con su propio cliente; registrada igualmente.",
	PurposeTimestamp:           "sello de tiempo",
	PurposeRevocation:          "consulta de revocación",
	PurposeTrustList:           "lista de confianza",
	PurposeWebDelivery:         "entrega a la página web",
	PurposeLocalAPI:            "servidor local de trebaruna",
	PurposeSigningServer:       "servidor de la sede",
	PurposeRemoteSigning:       "firma remota",
	PurposeUnattributed:        "sin motivo identificado",
	DocumentFingerprint:        "Huella SHA-256: %s",
	DocumentChanged:            "Atención: el documento cambió después de elegirlo. Se ha firmado la versión con huella %s.",
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
	LevelLabel:             "Livello",
	TSALabel:               "Autorità di marca temporale (TSA)",
	ReasonLabel:            "Motivo",
	LocationLabel:          "Luogo",
	ChooseButton:           "Scegli…",
	SignButton:             "Firma",
	SigningMessage:         "firma in corso…",
	MissingDocument:        "Scegli un documento da firmare.",
	MissingKey:             "Scegli il tuo certificato (.p12, .pfx o .pem).",
	MissingTSA:             "Il livello %s richiede un'autorità di marca temporale (TSA).",
	InvalidPage:            "La pagina del timbro parte da 1.",
	NoOutput:               "La firma non ha prodotto %s.",

	WelcomeTitle:   "trebaruna",
	WelcomeTagline: "Firma elettronica CAdES, PAdES e XAdES.\nSenza Electron, senza Java, senza codice proprietario.",
	WelcomePoint1:  "· Il timbro riporta i dati del tuo certificato.",
	WelcomePoint2:  "· Trascina il timbro in qualsiasi spazio della pagina.",
	WelcomePoint3:  "· Funziona offline; solo la TSA usa la rete.",
	WelcomeStart:   "Inizia",

	SuggestButton:              "Trova uno spazio libero",
	NoPreviewYet:               "Scegli un PDF per vedere la pagina e posizionare il timbro.",
	NoVisibleSeal:              "Questo formato non ha un timbro visibile: la firma è nel file .p7m o dentro l'XML.",
	RenderingMessage:           "Preparazione della pagina…",
	PreviewUnavailable:         "Impossibile mostrare la pagina: manca poppler (pdftoppm). La firma funziona comunque: il timbro andrà nell'angolo in basso a destra della pagina 1.",
	PageOf:                     "Pagina %d di %d",
	SealHint:                   "Fai clic sulla pagina per posizionare il timbro, trascinalo per spostarlo e tira l'angolo per ingrandirlo. Da tastiera, le frecce lo spostano.",
	SealCoversText:             "Il timbro copre del testo. Spostalo in uno spazio vuoto o premi «Trova uno spazio libero».",
	SealHolderPlaceholder:      "Titolare del certificato",
	NoSuggestion:               "Nessun altro spazio libero in questa pagina: posiziona il timbro a mano o cambia pagina.",
	StepDocument:               "Documento",
	StepCertificate:            "Certificato",
	StepSignature:              "Firma",
	ChooseDocument:             "Scegli documento…",
	ChooseCertificate:          "Scegli certificato…",
	ChangeButton:               "Cambia…",
	DropHint:                   "PDF, XML o qualsiasi altro file. Puoi anche trascinarlo nella finestra.",
	CertificateHint:            "File .p12, .pfx o .pem con il tuo certificato e la sua chiave.",
	DocumentSavedAs:            "Verrà salvato come %s",
	PassphrasePlaceholder:      "Password del certificato",
	CertificateReading:         "Lettura del certificato…",
	CertificateNeedsPassphrase: "Scrivi la password per leggere il certificato.",
	CertificateLocked:          "La password non apre questo certificato.",
	IssuedBy:                   "Emesso da %s",
	ValidUntil:                 "Valido fino al %s",
	StandingQualified:          "Certificato qualificato: la firma ha pieno valore legale (eIDAS).",
	StandingTrusted:            "Emittente affidabile: firma avanzata, ma il certificato non è qualificato.",
	StandingUntrusted:          "Nessuna lista di fiducia garantisce questo emittente: la firma sarà tecnicamente corretta, ma senza valore legale.",
	StandingExpired:            "Scaduto il %s: non può più firmare.",
	CertificateExpiresSoon:     "Scade tra %d giorni.",
	FormatPAdESLabel:           "PDF firmato (PAdES): si apre con qualsiasi lettore",
	FormatCAdESLabel:           "Busta .p7m (CAdES): quella richiesta da molti uffici",
	FormatXAdESLabel:           "XML firmato (XAdES)",
	FormatOnlyCAdES:            "Questo tipo di file si firma in una busta .p7m (CAdES).",
	SealOnPagePane:             "Il timbro andrà dove lo vedi nella pagina a destra.",
	MoreOptions:                "Altre opzioni",
	LevelBasicLabel:            "Base, senza marca temporale",
	LevelTimestampLabel:        "Con marca temporale (T)",
	LevelLongTermLabel:         "Validazione a lungo termine (LT)",
	LevelArchiveLabel:          "Archiviazione a lungo termine (LTA)",
	LevelHint:                  "La marca temporale prova quando è stata apposta la firma. LT e LTA verificano anche in rete se il certificato era revocato.",
	LocationPlaceholder:        "Città",
	SignedAs:                   "Firmato: %s",
	OpenSigned:                 "Apri",
	ShowFolder:                 "Cartella",
	CheckSignature:             "Verifica",
	TSAUserLabel:               "Utente TSA (se l'autorità lo richiede)",
	TSAPasswordLabel:           "Password TSA",
	TSAAccountHint:             "Alcune autorità, come quelle di Aruba o InfoCert, appongono la marca solo con un account. L'utente viene ricordato, la password no.",
	MenuFile:                   "File",
	MenuOpenDocument:           "Apri documento da firmare…",
	MenuChooseCertificate:      "Scegli certificato…",
	MenuCheckDocument:          "Verifica un documento firmato…",
	MenuSignature:              "Firma",
	MenuPreviousPage:           "Pagina precedente",
	MenuNextPage:               "Pagina successiva",
	MenuTools:                  "Strumenti",
	MenuRequests:               "Richieste dalle pagine web…",
	MenuHelp:                   "Aiuto",
	MenuManual:                 "Manuale",
	MenuAbout:                  "Informazioni su trebaruna",
	AboutText:                  "Firma elettronica CAdES, PAdES e XAdES senza codice proprietario.\nVersione %s\nLicenza AGPL-3.0-or-later.",
	UnknownVersion:             "sconosciuta (programma trebaruna non trovato)",
	CloseButton:                "Chiudi",
	RefreshButton:              "Aggiorna",
	OnlineRevocation:           "Verifica in rete se il certificato era revocato (OCSP)",
	CheckingMessage:            "Verifica in corso…",
	ExplainQualified:           "Il documento non è cambiato e la firma è qualificata: equivale a una firma autografa in tutta l'Unione europea.",
	ExplainAdvanced:            "Il documento non è cambiato e una lista di fiducia europea garantisce l'emittente del certificato.",
	ExplainUntrusted:           "Il documento non è cambiato, ma nessuna lista di fiducia garantisce l'emittente del certificato.",
	ExplainInvalid:             "Il documento non è cambiato, ma il certificato non poteva firmare in quel momento: era scaduto o revocato.",
	ExplainBroken:              "Il documento è cambiato dopo la firma: la firma non corrisponde più al contenuto.",
	ExplainUnknown:             "Con le informazioni disponibili non si può stabilire se la firma è valida.",
	MenuNetwork:                "Attività di rete…",
	NetworkTitle:               "Attività di rete di questa sessione",
	NetworkEmpty:               "In questa sessione non è stata aperta nessuna connessione. La firma di livello base e la verifica senza controllo di revoca non usano la rete.",
	NetworkSummary:             "Connessioni: %s",
	NetworkBytes:               "%s inviati, %s ricevuti",
	NetworkViaLibrary:          "Aperta da una libreria di terze parti con un proprio client; registrata comunque.",
	PurposeTimestamp:           "marca temporale",
	PurposeRevocation:          "verifica di revoca",
	PurposeTrustList:           "lista di fiducia",
	PurposeWebDelivery:         "consegna alla pagina web",
	PurposeLocalAPI:            "server locale di trebaruna",
	PurposeSigningServer:       "server del portale",
	PurposeRemoteSigning:       "firma remota",
	PurposeUnattributed:        "motivo non identificato",
	DocumentFingerprint:        "Impronta SHA-256: %s",
	DocumentChanged:            "Attenzione: il documento è cambiato dopo la scelta. È stata firmata la versione con impronta %s.",
}

var english = Catalogue{
	Language:               English,
	VerifySection:          "Check a signature",
	VerifyHint:             "Choose or drop a signed document: PDF, .p7m, .p7s or XML. It is checked offline against the European trust lists.",
	VerifyButton:           "Check",
	VerificationUnreadable: "The verification report could not be read.",
	SignTab:                "Sign",
	VerifyTab:              "Check",
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
	LevelLabel:             "Level",
	TSALabel:               "Timestamp authority (TSA)",
	ReasonLabel:            "Reason",
	LocationLabel:          "Location",
	ChooseButton:           "Choose…",
	SignButton:             "Sign",
	SigningMessage:         "signing…",
	MissingDocument:        "Choose a document to sign.",
	MissingKey:             "Choose your certificate (.p12, .pfx or .pem).",
	MissingTSA:             "Level %s needs a timestamp authority (TSA).",
	InvalidPage:            "Seal pages start at 1.",
	NoOutput:               "The signature did not produce %s.",

	WelcomeTitle:   "trebaruna",
	WelcomeTagline: "CAdES, PAdES and XAdES electronic signatures.\nNo Electron, no Java, no proprietary code.",
	WelcomePoint1:  "· The seal is filled from your certificate.",
	WelcomePoint2:  "· Drag the seal anywhere on the page.",
	WelcomePoint3:  "· Works offline; only the TSA uses the network.",
	WelcomeStart:   "Start",

	SuggestButton:              "Find free space",
	NoPreviewYet:               "Choose a PDF to see the page and place the seal.",
	NoVisibleSeal:              "This format has no visible seal: the signature travels in the .p7m file or inside the XML.",
	RenderingMessage:           "Preparing the page…",
	PreviewUnavailable:         "The page cannot be shown because poppler (pdftoppm) is missing. Signing still works: the seal goes in the bottom-right corner of page 1.",
	PageOf:                     "Page %d of %d",
	SealHint:                   "Click the page to place the seal, drag it to move it and pull its corner to enlarge it. With the keyboard, the arrow keys nudge it.",
	SealCoversText:             "The seal covers text in the document. Move it to an empty area or press \"Find free space\".",
	SealHolderPlaceholder:      "Certificate holder",
	NoSuggestion:               "No other free space on this page: place the seal by hand or change page.",
	StepDocument:               "Document",
	StepCertificate:            "Certificate",
	StepSignature:              "Signature",
	ChooseDocument:             "Choose document…",
	ChooseCertificate:          "Choose certificate…",
	ChangeButton:               "Change…",
	DropHint:                   "PDF, XML or any other file. You can also drop it on the window.",
	CertificateHint:            "A .p12, .pfx or .pem file with your certificate and its key.",
	DocumentSavedAs:            "Will be saved as %s",
	PassphrasePlaceholder:      "Certificate passphrase",
	CertificateReading:         "Reading the certificate…",
	CertificateNeedsPassphrase: "Type the passphrase to read the certificate.",
	CertificateLocked:          "The passphrase does not open this certificate.",
	IssuedBy:                   "Issued by %s",
	ValidUntil:                 "Valid until %s",
	StandingQualified:          "Qualified certificate: the signature has full legal effect (eIDAS).",
	StandingTrusted:            "Trusted issuer: an advanced signature, though the certificate is not qualified.",
	StandingUntrusted:          "No trusted list vouches for this issuer: the signature will be technically sound but carry no legal weight.",
	StandingExpired:            "Expired on %s: it can no longer sign.",
	CertificateExpiresSoon:     "Expires in %d days.",
	FormatPAdESLabel:           "Signed PDF (PAdES): opens in any reader",
	FormatCAdESLabel:           ".p7m envelope (CAdES): what some offices require",
	FormatXAdESLabel:           "Signed XML (XAdES)",
	FormatOnlyCAdES:            "This kind of file is signed inside a .p7m envelope (CAdES).",
	SealOnPagePane:             "The seal goes where you see it on the page to the right.",
	MoreOptions:                "More options",
	LevelBasicLabel:            "Basic, no timestamp",
	LevelTimestampLabel:        "With timestamp (T)",
	LevelLongTermLabel:         "Long-term validation (LT)",
	LevelArchiveLabel:          "Long-term archive (LTA)",
	LevelHint:                  "A timestamp proves when the signature was made. LT and LTA also ask over the network whether the certificate was revoked.",
	LocationPlaceholder:        "City",
	SignedAs:                   "Signed: %s",
	OpenSigned:                 "Open",
	ShowFolder:                 "Folder",
	CheckSignature:             "Check",
	TSAUserLabel:               "TSA user (if the authority asks for one)",
	TSAPasswordLabel:           "TSA password",
	TSAAccountHint:             "Some authorities, such as Aruba's or InfoCert's, only timestamp with an account. The user is remembered; the password is not.",
	MenuFile:                   "File",
	MenuOpenDocument:           "Open document to sign…",
	MenuChooseCertificate:      "Choose certificate…",
	MenuCheckDocument:          "Check a signed document…",
	MenuSignature:              "Signature",
	MenuPreviousPage:           "Previous page",
	MenuNextPage:               "Next page",
	MenuTools:                  "Tools",
	MenuRequests:               "Requests from web pages…",
	MenuHelp:                   "Help",
	MenuManual:                 "Manual",
	MenuAbout:                  "About trebaruna",
	AboutText:                  "CAdES, PAdES and XAdES electronic signatures without proprietary code.\nVersion %s\nLicensed AGPL-3.0-or-later.",
	UnknownVersion:             "unknown (the trebaruna program was not found)",
	CloseButton:                "Close",
	RefreshButton:              "Refresh",
	OnlineRevocation:           "Ask over the network whether the certificate was revoked (OCSP)",
	CheckingMessage:            "Checking…",
	ExplainQualified:           "The document has not changed and the signature is qualified: it equals a handwritten signature throughout the European Union.",
	ExplainAdvanced:            "The document has not changed and a European trusted list vouches for the certificate's issuer.",
	ExplainUntrusted:           "The document has not changed, but no trusted list vouches for the certificate's issuer.",
	ExplainInvalid:             "The document has not changed, but the certificate could not sign at that moment: it was expired or revoked.",
	ExplainBroken:              "The document changed after it was signed: the signature no longer matches its content.",
	ExplainUnknown:             "The available information is not enough to decide whether the signature is valid.",
	MenuNetwork:                "Network activity…",
	NetworkTitle:               "Network activity in this session",
	NetworkEmpty:               "No connection has been made in this session. Basic signatures and checks without revocation queries do not use the network.",
	NetworkSummary:             "Connections: %s",
	NetworkBytes:               "%s sent, %s received",
	NetworkViaLibrary:          "Opened by a third-party library with its own client; recorded all the same.",
	PurposeTimestamp:           "timestamp",
	PurposeRevocation:          "revocation check",
	PurposeTrustList:           "trusted list",
	PurposeWebDelivery:         "delivery to the web page",
	PurposeLocalAPI:            "trebaruna's local server",
	PurposeSigningServer:       "site's signing server",
	PurposeRemoteSigning:       "remote signing",
	PurposeUnattributed:        "no identified purpose",
	DocumentFingerprint:        "SHA-256 fingerprint: %s",
	DocumentChanged:            "Warning: the document changed after it was chosen. The version with fingerprint %s was signed.",
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

// NoOutputMessage formats the missing-artefact error.
func (c Catalogue) NoOutputMessage(path string) string {
	return fmt.Sprintf(c.NoOutput, path)
}
