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

	// Catalan, Galician and Basque are co-official in Spain, and AutoFirma
	// speaks them.
	Catalan  Language = "ca"
	Galician Language = "gl"
	Basque   Language = "eu"
)

// Languages lists every interface language, the default first.
func Languages() []Language {
	return []Language{Spanish, Catalan, Galician, Basque, Italian, English}
}

// ParseLanguage maps a locale name onto a supported language.
//
// It accepts "it", "it-IT", "es_ES" and similar, so the value can come straight
// from LANG without normalisation at the call site.
func ParseLanguage(raw string) Language {
	if len(raw) < 2 {
		return Spanish
	}
	for _, language := range Languages() {
		if raw[:2] == string(language) {
			return language
		}
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

	// The card source of the signing form.
	KeyFromFile                string
	KeyFromCard                string
	KeyFromFirefox             string
	KeyFromRemote              string
	RemoteAddressLabel         string
	RemoteUserLabel            string
	RemotePasswordLabel        string
	RemoteClientLabel          string
	RemoteAccountHint          string
	RemoteOTPLabel             string
	SearchRemote               string
	NoRemoteCredentials        string
	RemotePINPlaceholder       string
	RemoteWhere                string
	MissingService             string
	FirefoxWhere               string
	FirefoxPasswordPlaceholder string
	NoFirefoxCertificates      string
	SearchCards                string
	CardsSearching             string
	NoCards                    string
	CardPlaceholder            string
	CardSigningRole            string
	CardOtherRole              string
	CardWhere                  string
	PINPlaceholder             string
	PINPadHint                 string
	PINCountLow                string
	PINFinalTry                string
	CardLocked                 string
	PINExpired                 string
	MissingPIN                 string
	WrongPIN                   string
	WrongPINFinalTry           string
	WrongPINNowLocked          string
	BatchNotTried              string
	FormatPAdESLabel           string
	FormatCAdESLabel           string
	FormatXAdESLabel           string
	FormatODFLabel             string
	FormatOOXMLLabel           string
	RubricLabel                string
	ChooseRubric               string
	RubricHint                 string
	RemoveRubric               string
	RubricInvalid              string
	PreviewApproximate         string
	PreviousPage               string
	NextPage                   string
	FormatOnlyCAdES            string
	SealOnPagePane             string
	FormFieldLabel             string
	FormFieldNone              string
	FormFieldOption            string
	FormFieldsOffered          string
	FormFieldSealHint          string
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
	MenuFile                 string
	MenuOpenDocument         string
	MenuChooseCertificate    string
	MenuCheckDocument        string
	MenuSignature            string
	MenuPreviousPage         string
	MenuNextPage             string
	MenuTools                string
	PageTitle                string
	PageSite                 string
	PageAppName              string
	PageOpSign               string
	PageOpCosign             string
	PageOpCountersign        string
	PageOpSignAndSave        string
	PageOpSelectCert         string
	PageOpSave               string
	PageOpBatch              string
	PageOpBatchOne           string
	PageFormat               string
	PagePolicy               string
	PageRoles                string
	PagePlace                string
	PageData                 string
	PageDataURL              string
	PageChooseFile           string
	PageFilters              string
	PageWarnDES              string
	PageWarnDownload         string
	PageWarnBatch            string
	PageWarnFilters          string
	PageWarnTriphase         string
	PageWarnBare             string
	PageWarnDigest           string
	PageWarnReferenced       string
	PageSealTitle            string
	PageSealOptional         string
	PageWarnSealLater        string
	PageUseRemembered        string
	PageRememberedHolder     string
	PageListening            string
	PageNextRequest          string
	PageSessionClosed        string
	PageLocalTLSMissing      string
	PageInstallLocalTLS      string
	MenuLocalChannel         string
	LocalChannelExplain      string
	LocalChannelInstalled    string
	LocalChannelNotInstalled string
	LocalChannelRemove       string
	PageRejected             string
	PageApprove              string
	PageApproveCertificate   string
	PageApproveSave          string
	PageDecline              string
	PageClose                string
	PageSaveTo               string
	PageDocument             string
	PageWorking              string
	PageDone                 string
	PageDeclined             string
	PageFailed               string
	MissingSaveTo            string
	PageKeyTitle             string
	MenuCard                 string
	MenuChangePIN            string
	MenuUnlockPIN            string
	MenuChangePUK            string
	ChangePUKTitle           string
	ChangePUKHint            string
	NewPUKLabel              string
	RepeatPUKLabel           string
	ChangePUKButton          string
	PUKChanged               string
	CurrentPUKLabel          string
	ChangePINTitle           string
	UnlockPINTitle           string
	ChangePINHint            string
	UnlockPINHint            string
	PINDialogCard            string
	PINDialogOnlyCard        string
	CurrentPINLabel          string
	PUKLabel                 string
	NewPINLabel              string
	RepeatPINLabel           string
	ChangePINButton          string
	UnlockPINButton          string
	CancelButton             string
	TalkingToCard            string
	PINChanged               string
	CardUnlocked             string
	PINMismatch              string
	MissingPUK               string
	WrongPUK                 string
	WrongPUKFinalTry         string
	WrongPUKNowLocked        string
	PUKLocked                string
	NewPINRejected           string
	NewPINTooShort           string
	NewPINTooLong            string
	MenuRequests             string
	MenuEncrypt              string
	MenuOpenEnvelope         string
	EnvelopesTitle           string
	EncryptSection           string
	EncryptIntro             string
	RecipientsLabel          string
	AddRecipient             string
	RemoveRecipient          string
	NoRecipients             string
	EncryptButton            string
	EncryptingMessage        string
	EncryptedAs              string
	MissingRecipient         string
	OpenSection              string
	ChooseEnvelope           string
	EnvelopeHint             string
	OpensWith                string
	NoKeyToOpen              string
	GoToCertificate          string
	OpenEnvelopeButton       string
	OpeningMessage           string
	OpenedAs                 string
	MenuHelp                 string
	MenuManual               string
	MenuAbout                string
	AboutText                string
	UnknownVersion           string
	CloseButton              string
	RefreshButton            string

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
	MenuNetwork            string
	NetworkTitle           string
	NetworkEmpty           string
	NetworkSummary         string
	NetworkBytes           string
	NetworkViaLibrary      string
	PurposeTimestamp       string
	PurposeRevocation      string
	PurposeTrustList       string
	PurposeWebDelivery     string
	PurposeLocalAPI        string
	PurposeSigningServer   string
	PurposeRemoteSigning   string
	PurposeUnattributed    string
	DocumentFingerprint    string
	DocumentChanged        string
	AboutCardsYes          string
	AboutCardsNo           string
	AboutRevision          string
	AboutDependencies      string
	InvisibleSignature     string
	InvisibleExplained     string
	FormatDetachedLabel    string
	ExtractButton          string
	ExtractedAs            string
	ExtractDocumentsButton string
	ExtractedFolder        string
	ReportButton           string
	ReportFileName         string
	ReportSavedAs          string
	FormatCosignLabel      string
	FormatCountersignLabel string
	FormatWrapLabel        string
	CountersignatureOf     string
	FormatEachLabel        string
	FormatASiCSLabel       string
	FormatASiCELabel       string
	FormatFacturaELabel    string
	InvoiceRoleLabel       string
	InvoiceRoleIssuer      string
	InvoiceRoleReceiver    string
	InvoiceRoleThird       string
	PolicyLabel            string
	PolicyNoneLabel        string
	PolicyAGELabel         string
	PolicyAGE18Label       string
	PolicyFacturaELabel    string
	PolicyFacturaE30Label  string
	PolicyHint             string
	InvoiceDetected        string
	PolicyNotForFormat     string
	InvoiceRoleMissing     string
	BatchTitle             string
	BatchSeal              string
	BatchProgress          string
	BatchDone              string
	MenuSignFolder         string
}

// For returns the catalogue for a language.
func For(language Language) Catalogue {
	switch language {
	case Italian:
		return italian
	case English:
		return english
	case Catalan:
		return catalan
	case Galician:
		return galician
	case Basque:
		return basque
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
	SealHint:                   "Haz clic en la página para colocar el sello, arrástralo para moverlo y tira de la esquina para ampliarlo. Con el teclado, las flechas lo desplazan y + y − lo agrandan o lo encogen.",
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
	KeyFromFile:                "Archivo",
	KeyFromCard:                "Tarjeta",
	KeyFromFirefox:             "Firefox",
	KeyFromRemote:              "Servicio remoto",
	RemoteAddressLabel:         "Dirección del servicio (CSC)",
	RemoteUserLabel:            "Usuario",
	RemotePasswordLabel:        "Contraseña",
	RemoteClientLabel:          "Identificador de cliente para entrar desde el navegador (OAuth2)",
	RemoteAccountHint:          "Con usuario y contraseña, o con el identificador que el proveedor da a trebaruna para entrar y autorizar en tu navegador. El documento no sale de aquí: solo viaja su huella.",
	RemoteOTPLabel:             "Código de un solo uso (si el servicio lo pide)",
	SearchRemote:               "Buscar credenciales",
	NoRemoteCredentials:        "Escribe la dirección del servicio y cómo entrar, y pulsa «Buscar credenciales».",
	RemotePINPlaceholder:       "PIN de la firma remota (si lo pide)",
	RemoteWhere:                "Guardada por %s: firma allí; de aquí solo sale la huella del documento.",
	MissingService:             "Escribe la dirección del servicio de firma remota.",
	FirefoxWhere:               "En el almacén de certificados de Firefox: se usa allí mismo, sin exportarlo.",
	FirefoxPasswordPlaceholder: "Contraseña maestra de Firefox",
	NoFirefoxCertificates:      "Firefox no guarda ningún certificado con su clave. Impórtalo en Firefox (Ajustes, Privacidad y seguridad, Ver certificados) o elige otro origen.",
	SearchCards:                "Buscar tarjetas",
	CardsSearching:             "Buscando tarjetas en los lectores…",
	NoCards:                    "No hay ninguna tarjeta con certificados en los lectores. Inserta la tarjeta y pulsa «Buscar tarjetas».",
	CardPlaceholder:            "Elige el certificado de la tarjeta",
	CardSigningRole:            "para firmar",
	CardOtherRole:              "otro uso",
	CardWhere:                  "En la tarjeta «%s», %s.",
	PINPlaceholder:             "PIN de la tarjeta",
	PINPadHint:                 "Este lector pide el PIN en su propio teclado al firmar.",
	PINCountLow:                "Ya se ha introducido un PIN erróneo: quedan pocos intentos antes de que la tarjeta se bloquee.",
	PINFinalTry:                "Queda un solo intento: un PIN erróneo más bloqueará la tarjeta.",
	CardLocked:                 "La tarjeta está bloqueada: desbloquéala con su PUK.",
	PINExpired:                 "La tarjeta pide cambiar su PIN antes de firmar.",
	MissingPIN:                 "Escribe el PIN de la tarjeta.",
	WrongPIN:                   "La tarjeta ha rechazado el PIN. No se ha firmado nada.",
	WrongPINFinalTry:           "La tarjeta ha rechazado el PIN. Queda un solo intento: un error más la bloqueará.",
	WrongPINNowLocked:          "La tarjeta ha rechazado el PIN y se ha bloqueado: desbloquéala con su PUK.",
	BatchNotTried:              "no se ha intentado, para no gastar otro intento de PIN",
	FormatPAdESLabel:           "PDF firmado (PAdES): se abre en cualquier lector",
	FormatCAdESLabel:           "Sobre .p7m (CAdES): el que piden algunas administraciones",
	FormatXAdESLabel:           "XML firmado (XAdES)",
	FormatODFLabel:             "Documento de LibreOffice firmado por dentro (ODF)",
	FormatOOXMLLabel:           "Documento de Office firmado por dentro (OOXML)",
	RubricLabel:                "Rúbrica (opcional)",
	ChooseRubric:               "Elegir imagen de la firma…",
	RubricHint:                 "Una imagen PNG o JPEG de tu firma manuscrita. Va en el sello junto a los datos del certificado, nunca sola.",
	RemoveRubric:               "Quitar la rúbrica",
	RubricInvalid:              "Esa imagen no sirve como rúbrica: tiene que ser PNG o JPEG, de hasta 4 MiB y 4096 píxeles de lado.",
	FormatOnlyCAdES:            "Este tipo de fichero se firma dentro de un sobre .p7m (CAdES).",
	SealOnPagePane:             "El sello irá donde lo ves en la página de la derecha.",
	FormFieldLabel:             "Campo de firma del formulario",
	FormFieldNone:              "Ninguno: colocar el sello en la página",
	FormFieldOption:            "%s (página %d)",
	FormFieldsOffered:          "Este PDF reserva campos para firmar: elige uno para que el sello vaya en él.",
	FormFieldSealHint:          "El formulario reserva este recuadro para la firma: el sello irá aquí y no se mueve.",
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
	PageTitle:                  "Una página web pide tu firma",
	PageSite:                   "La respuesta irá a %s.",
	PageAppName:                "La página dice llamarse «%s».",
	PageOpSign:                 "Firmar un documento",
	PageOpCosign:               "Añadir tu firma a un documento ya firmado",
	PageOpCountersign:          "Contrafirmar las firmas de un documento",
	PageOpSignAndSave:          "Firmar un documento y guardarlo",
	PageOpSelectCert:           "Darle tu certificado, sin firmar nada",
	PageOpSave:                 "Guardar un fichero en tu equipo",
	PageOpBatch:                "Firmar %d documentos",
	PageOpBatchOne:             "Firmar 1 documento",
	PageFormat:                 "Formato: %s",
	PagePolicy:                 "La firma declarará la política %s",
	PageRoles:                  "La firma declarará el rol %s",
	PagePlace:                  "La firma declarará el lugar %s",
	PageData:                   "Datos: %d bytes, huella SHA-256 %s",
	PageDataURL:                "Los datos se descargarán de %s si apruebas.",
	PageChooseFile:             "La página no envía el documento: elige cuál firmar.",
	PageFilters:                "Solo acepta certificados que cumplan: %s",
	PageWarnDES:                "La respuesta viaja a la sede cifrada con DES simple y una clave de 8 cifras: quien la vea puede leerla.",
	PageWarnDownload:           "Los datos se descargarán de %s cuando apruebes.",
	PageWarnBatch:              "Los documentos se quedan en la sede: firmas lo que su servidor prepara a partir de ellos, y trebaruna no puede enseñártelo.",
	PageWarnFilters:            "La página pone condiciones a los certificados que trebaruna no entiende; ningún certificado las cumple.",
	PageWarnTriphase:           "La firma la prepara el servidor de la sede (%s): firmas lo que ese servidor calcula, y trebaruna no puede enseñártelo.",
	PageWarnBare:               "Una firma desnuda (NONE) no dice nada de lo que firma: si estos bytes son la parte firmada de otra firma, firmas todo lo que esa cubre, y trebaruna no puede enseñártelo.",
	PageWarnDigest:             "La página envía solo el resumen %s de un documento, %s, no el documento: trebaruna no puede enseñarlo; si tienes el documento, compara su resumen con este.",
	PageWarnReferenced:         "La firma cubre documentos que trebaruna no ve, solo su dirección y su resumen: %s. Compara los resúmenes con los de los documentos si los tienes.",
	PageSealTitle:              "Coloca el sello en la página: arrástralo o dibuja su caja. La página pidió una firma visible.",
	PageSealOptional:           "Añadir un sello visible",
	PageWarnSealLater:          "La página pide un sello visible, pero el documento se descarga solo después de aprobar: la firma será invisible.",
	PageUseRemembered:          "Usar el mismo certificado que en la petición anterior",
	PageRememberedHolder:       "%s: la página pidió conservarlo mientras dure la conexión.",
	PageListening:              "Esperando a que la página se conecte con trebaruna en este equipo (puerto %d)…",
	PageNextRequest:            "Esperando la siguiente petición de la página…",
	PageSessionClosed:          "La página ha cerrado la conexión con trebaruna.",
	PageLocalTLSMissing:        "Esta página se comunica con trebaruna por un canal cifrado en este equipo, que necesita el certificado local de trebaruna. Se instala solo para tu usuario: su raíz no conserva clave privada y solo vale para 127.0.0.1.",
	PageInstallLocalTLS:        "Instalar el certificado local",
	MenuLocalChannel:           "Canal local para sedes…",
	LocalChannelExplain:        "Las sedes que usan AutoFirma hablan con el programa por un canal cifrado en este equipo. Para que el navegador lo acepte, trebaruna instala para tu usuario (Firefox y Chromium) una raíz que solo vale para 127.0.0.1 y cuya clave privada se destruye al crearla: no puede firmar ningún otro certificado.",
	LocalChannelInstalled:      "Instalado para tu usuario.",
	LocalChannelNotInstalled:   "No instalado.",
	LocalChannelRemove:         "Retirar",
	PageRejected:               "La página no acepta ese certificado (%s). Elige otro.",
	PageApprove:                "Firmar y enviar",
	PageApproveCertificate:     "Enviar el certificado",
	PageApproveSave:            "Guardar",
	PageDecline:                "Rechazar",
	PageClose:                  "Cerrar",
	PageSaveTo:                 "Guardar en…",
	PageDocument:               "Documento a firmar…",
	PageWorking:                "Trabajando; la respuesta irá a %s…",
	PageDone:                   "Hecho: la respuesta ha llegado a %s.",
	PageDeclined:               "Has rechazado la petición; la página lo sabe.",
	PageFailed:                 "No se ha completado: %s",
	MissingSaveTo:              "Elige dónde guardar.",
	PageKeyTitle:               "Con qué certificado",
	MenuCard:                   "Tarjeta",
	MenuChangePIN:              "Cambiar el PIN…",
	MenuUnlockPIN:              "Desbloquear con el PUK…",
	MenuChangePUK:              "Cambiar el PUK…",
	ChangePUKTitle:             "Cambiar el PUK",
	ChangePUKHint:              "Escribe el PUK actual y el nuevo dos veces. Si te equivocas con el PUK, la tarjeta cuenta un intento; agotados, solo quien la emitió puede desbloquearla.",
	NewPUKLabel:                "PUK nuevo",
	RepeatPUKLabel:             "Repite el PUK nuevo",
	ChangePUKButton:            "Cambiar el PUK",
	PUKChanged:                 "PUK cambiado: la tarjeta ya acepta el nuevo.",
	CurrentPUKLabel:            "PUK actual",
	ChangePINTitle:             "Cambiar el PIN de la tarjeta",
	UnlockPINTitle:             "Desbloquear la tarjeta con el PUK",
	ChangePINHint:              "La tarjeta comprueba el PIN actual una sola vez: si es erróneo, gasta uno de sus pocos intentos.",
	UnlockPINHint:              "El PUK viene en el sobre de la tarjeta, junto al PIN. Sirve también si has olvidado el PIN. Sus intentos también son pocos: si se bloquea, solo el emisor puede desbloquear la tarjeta.",
	PINDialogCard:              "Tarjeta «%s».",
	PINDialogOnlyCard:          "La tarjeta del lector.",
	CurrentPINLabel:            "PIN actual",
	PUKLabel:                   "PUK",
	NewPINLabel:                "PIN nuevo",
	RepeatPINLabel:             "Repite el PIN nuevo",
	ChangePINButton:            "Cambiar el PIN",
	UnlockPINButton:            "Desbloquear",
	CancelButton:               "Cancelar",
	TalkingToCard:              "Hablando con la tarjeta…",
	PINChanged:                 "PIN cambiado: la tarjeta ya acepta el nuevo.",
	CardUnlocked:               "Tarjeta desbloqueada: el PIN nuevo ya funciona.",
	PINMismatch:                "Los dos PIN nuevos no coinciden.",
	MissingPUK:                 "Escribe el PUK de la tarjeta.",
	WrongPUK:                   "La tarjeta ha rechazado el PUK. No se ha cambiado nada.",
	WrongPUKFinalTry:           "La tarjeta ha rechazado el PUK. Queda un solo intento: otro error lo bloqueará y solo el emisor podrá desbloquear la tarjeta.",
	WrongPUKNowLocked:          "La tarjeta ha rechazado el PUK y lo ha bloqueado: solo el emisor puede desbloquearla.",
	PUKLocked:                  "El PUK está bloqueado: solo el emisor de la tarjeta puede desbloquearla.",
	NewPINRejected:             "La tarjeta no acepta ese PIN nuevo.",
	NewPINTooShort:             "El PIN nuevo es demasiado corto: la tarjeta pide al menos %s caracteres.",
	NewPINTooLong:              "El PIN nuevo es demasiado largo: la tarjeta admite como mucho %s caracteres.",
	MenuRequests:               "Peticiones de páginas web…",
	MenuEncrypt:                "Cifrar para otros…",
	MenuOpenEnvelope:           "Abrir un sobre cifrado…",
	EnvelopesTitle:             "Sobres cifrados",
	EncryptSection:             "Cifrar para otros",
	EncryptIntro:               "Solo podrán abrirlo las personas cuyos certificados añadas. Añade el tuyo si también quieres abrirlo.",
	RecipientsLabel:            "Destinatarios",
	AddRecipient:               "Añadir certificado…",
	RemoveRecipient:            "Quitar",
	NoRecipients:               "Ningún destinatario todavía.",
	EncryptButton:              "Cifrar",
	EncryptingMessage:          "Cifrando…",
	EncryptedAs:                "Cifrado como %s. Lo pueden abrir: %s.",
	MissingRecipient:           "Añade el certificado de al menos un destinatario.",
	OpenSection:                "Abrir un sobre",
	ChooseEnvelope:             "Elegir sobre (.p7e)…",
	EnvelopeHint:               "Un .p7e que te han enviado cifrado para tu certificado.",
	OpensWith:                  "Se abre con el certificado elegido para firmar: %s.",
	NoKeyToOpen:                "Elige tu certificado en Firmar (paso 2) para abrir sobres.",
	GoToCertificate:            "Elegir certificado",
	OpenEnvelopeButton:         "Abrir sobre",
	OpeningMessage:             "Abriendo…",
	OpenedAs:                   "Abierto como %s (%s).",
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
	AboutCardsYes:              "Admite tarjetas y tokens (PKCS#11).",
	AboutCardsNo:               "Esta compilación no admite tarjetas: es la versión estática sin cgo.",
	AboutRevision:              "Revisión del código: %s",
	AboutDependencies:          "Dependencias y licencias (%d)",
	InvisibleSignature:         "Firma invisible (sin sello en la página)",
	InvisibleExplained:         "Firma invisible: el PDF queda firmado y cualquier lector lo muestra en su panel de firmas, pero no se dibuja ningún sello en la página.",
	FormatDetachedLabel:        "Firma separada .p7s (CAdES): el documento no se modifica",
	ExtractButton:              "Extraer el documento firmado",
	ExtractedAs:                "Documento extraído en %s. Extraer no comprueba nada: la comprobación es la de arriba.",
	ExtractDocumentsButton:     "Extraer los documentos del contenedor",
	ExtractedFolder:            "Documentos extraídos en %s. Extraer no comprueba nada: la comprobación es la de arriba.",
	ReportButton:               "Guardar informe…",
	ReportFileName:             "%s - informe.pdf",
	ReportSavedAs:              "Informe guardado en %s.",
	FormatCosignLabel:          "Añadir una firma paralela: firmas lo mismo que los demás",
	FormatCountersignLabel:     "Contrafirmar: firmas sobre las firmas que ya tiene",
	FormatWrapLabel:            "Envolver en otro sobre .p7m (modo antiguo)",
	CountersignatureOf:         "Contrafirma de la firma %s",
	FormatEachLabel:            "Cada uno en su formato: PDF firmado, XML firmado, .p7m para el resto",
	FormatASiCSLabel:           "Contenedor ASiC-S (.asics): el documento y su firma juntos",
	FormatASiCELabel:           "Un contenedor ASiC-E con todos (.asice), bajo una sola firma",
	FormatFacturaELabel:        "Factura FacturaE: firma dentro, con la política de FacturaE",
	InvoiceRoleLabel:           "Firmas la factura como",
	InvoiceRoleIssuer:          "emisor",
	InvoiceRoleReceiver:        "receptor",
	InvoiceRoleThird:           "tercero",
	PolicyLabel:                "Política de firma que declara",
	PolicyNoneLabel:            "Ninguna",
	PolicyAGELabel:             "AGE 1.9 (Administración General del Estado)",
	PolicyAGE18Label:           "AGE 1.8",
	PolicyFacturaELabel:        "FacturaE 3.1",
	PolicyFacturaE30Label:      "FacturaE 3.0",
	PolicyHint:                 "Solo si la sede o el destinatario lo piden: la firma declara seguir esa política.",
	InvoiceDetected:            "Es una factura FacturaE: se firma dentro, con la política de FacturaE y tu papel en ella.",
	PolicyNotForFormat:         "Esa política no se puede declarar en este formato.",
	InvoiceRoleMissing:         "Una factura FacturaE se firma con su política y como emisor, receptor o tercero.",
	BatchTitle:                 "%d documentos",
	BatchSeal:                  "En un lote, cada PDF lleva el sello en la esquina inferior derecha de su primera página.",
	BatchProgress:              "Firmando %d de %d…",
	BatchDone:                  "Firmados %d de %d.",
	MenuSignFolder:             "Firmar una carpeta…",
	PreviewApproximate:         "Es un esbozo de trebaruna: el texto va en otra tipografía. Con poppler (pdftoppm) instalado verás la página exacta.",
	PreviousPage:               "Página anterior",
	NextPage:                   "Página siguiente",
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
	SealHint:                   "Fai clic sulla pagina per posizionare il timbro, trascinalo per spostarlo e tira l'angolo per ingrandirlo. Da tastiera, le frecce lo spostano e + e − lo ingrandiscono o lo rimpiccioliscono.",
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
	KeyFromFile:                "File",
	KeyFromCard:                "Carta",
	KeyFromFirefox:             "Firefox",
	KeyFromRemote:              "Servizio remoto",
	RemoteAddressLabel:         "Indirizzo del servizio (CSC)",
	RemoteUserLabel:            "Utente",
	RemotePasswordLabel:        "Password",
	RemoteClientLabel:          "Identificativo client per l'accesso dal browser (OAuth2)",
	RemoteAccountHint:          "Con utente e password, oppure con l'identificativo che il fornitore dà a trebaruna per accedere e autorizzare nel tuo browser. Il documento non esce da qui: viaggia solo la sua impronta.",
	RemoteOTPLabel:             "Codice monouso (se il servizio lo chiede)",
	SearchRemote:               "Cerca credenziali",
	NoRemoteCredentials:        "Scrivi l'indirizzo del servizio e come accedere, poi premi «Cerca credenziali».",
	RemotePINPlaceholder:       "PIN della firma remota (se richiesto)",
	RemoteWhere:                "Custodita da %s: firma lì; da qui esce solo l'impronta del documento.",
	MissingService:             "Scrivi l'indirizzo del servizio di firma remota.",
	FirefoxWhere:               "Nell'archivio certificati di Firefox: viene usato lì, senza esportarlo.",
	FirefoxPasswordPlaceholder: "Password principale di Firefox",
	NoFirefoxCertificates:      "Firefox non conserva alcun certificato con la sua chiave. Importalo in Firefox (Impostazioni, Privacy e sicurezza, Mostra certificati) o scegli un'altra origine.",
	SearchCards:                "Cerca carte",
	CardsSearching:             "Ricerca delle carte nei lettori…",
	NoCards:                    "Nessuna carta con certificati nei lettori. Inserisci la carta e premi «Cerca carte».",
	CardPlaceholder:            "Scegli il certificato della carta",
	CardSigningRole:            "per firmare",
	CardOtherRole:              "altro uso",
	CardWhere:                  "Sulla carta «%s», %s.",
	PINPlaceholder:             "PIN della carta",
	PINPadHint:                 "Questo lettore chiede il PIN sulla propria tastiera al momento della firma.",
	PINCountLow:                "È già stato inserito un PIN errato: restano pochi tentativi prima che la carta si blocchi.",
	PINFinalTry:                "Resta un solo tentativo: un altro PIN errato bloccherà la carta.",
	CardLocked:                 "La carta è bloccata: sbloccala con il PUK.",
	PINExpired:                 "La carta chiede di cambiare il PIN prima di firmare.",
	MissingPIN:                 "Scrivi il PIN della carta.",
	WrongPIN:                   "La carta ha rifiutato il PIN. Non è stato firmato nulla.",
	WrongPINFinalTry:           "La carta ha rifiutato il PIN. Resta un solo tentativo: un altro errore la bloccherà.",
	WrongPINNowLocked:          "La carta ha rifiutato il PIN e si è bloccata: sbloccala con il PUK.",
	BatchNotTried:              "non tentato, per non sprecare un altro tentativo di PIN",
	FormatPAdESLabel:           "PDF firmato (PAdES): si apre con qualsiasi lettore",
	FormatCAdESLabel:           "Busta .p7m (CAdES): quella richiesta da molti uffici",
	FormatXAdESLabel:           "XML firmato (XAdES)",
	FormatODFLabel:             "Documento LibreOffice firmato al suo interno (ODF)",
	FormatOOXMLLabel:           "Documento Office firmato al suo interno (OOXML)",
	RubricLabel:                "Firma autografa (facoltativa)",
	ChooseRubric:               "Scegli l'immagine della firma…",
	RubricHint:                 "Un'immagine PNG o JPEG della tua firma autografa. Va nel sigillo accanto ai dati del certificato, mai da sola.",
	RemoveRubric:               "Togli la firma autografa",
	RubricInvalid:              "Quell'immagine non può fare da firma autografa: deve essere PNG o JPEG, al massimo 4 MiB e 4096 pixel per lato.",
	FormatOnlyCAdES:            "Questo tipo di file si firma in una busta .p7m (CAdES).",
	SealOnPagePane:             "Il timbro andrà dove lo vedi nella pagina a destra.",
	FormFieldLabel:             "Campo firma del modulo",
	FormFieldNone:              "Nessuno: posiziona il timbro sulla pagina",
	FormFieldOption:            "%s (pagina %d)",
	FormFieldsOffered:          "Questo PDF prevede campi per la firma: scegline uno perché il timbro vada lì.",
	FormFieldSealHint:          "Il modulo riserva questo riquadro alla firma: il timbro andrà qui e non si sposta.",
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
	PageTitle:                  "Una pagina web chiede la tua firma",
	PageSite:                   "La risposta andrà a %s.",
	PageAppName:                "La pagina dice di chiamarsi «%s».",
	PageOpSign:                 "Firmare un documento",
	PageOpCosign:               "Aggiungere la tua firma a un documento già firmato",
	PageOpCountersign:          "Controfirmare le firme di un documento",
	PageOpSignAndSave:          "Firmare un documento e salvarlo",
	PageOpSelectCert:           "Darle il tuo certificato, senza firmare nulla",
	PageOpSave:                 "Salvare un file sul tuo computer",
	PageOpBatch:                "Firmare %d documenti",
	PageOpBatchOne:             "Firmare 1 documento",
	PageFormat:                 "Formato: %s",
	PagePolicy:                 "La firma dichiarerà la politica %s",
	PageRoles:                  "La firma dichiarerà il ruolo %s",
	PagePlace:                  "La firma dichiarerà il luogo %s",
	PageData:                   "Dati: %d byte, impronta SHA-256 %s",
	PageDataURL:                "I dati verranno scaricati da %s se approvi.",
	PageChooseFile:             "La pagina non invia il documento: scegli quale firmare.",
	PageFilters:                "Accetta solo certificati che soddisfano: %s",
	PageWarnDES:                "La risposta viaggia verso il sito cifrata con DES semplice e una chiave di 8 cifre: chi la vede può leggerla.",
	PageWarnDownload:           "I dati verranno scaricati da %s quando approvi.",
	PageWarnBatch:              "I documenti restano sul sito: firmi ciò che il suo server prepara da essi, e trebaruna non può mostrartelo.",
	PageWarnFilters:            "La pagina pone ai certificati condizioni che trebaruna non capisce; nessun certificato le soddisfa.",
	PageWarnTriphase:           "La firma la prepara il server del sito (%s): firmi ciò che quel server calcola, e trebaruna non può mostrartelo.",
	PageWarnBare:               "Una firma nuda (NONE) non dice nulla di ciò che firma: se questi byte sono la parte firmata di un'altra firma, firmi tutto ciò che quella copre, e trebaruna non può mostrartelo.",
	PageWarnDigest:             "La pagina invia solo l'impronta %s di un documento, %s, non il documento: trebaruna non può mostrarlo; se hai il documento, confronta la sua impronta con questa.",
	PageWarnReferenced:         "La firma copre documenti che trebaruna non vede, solo il loro indirizzo e la loro impronta: %s. Confronta le impronte con quelle dei documenti, se li hai.",
	PageSealTitle:              "Posiziona il sigillo sulla pagina: trascinalo o disegna il suo riquadro. La pagina ha chiesto una firma visibile.",
	PageSealOptional:           "Aggiungi un sigillo visibile",
	PageWarnSealLater:          "La pagina chiede un sigillo visibile, ma il documento si scarica solo dopo l'approvazione: la firma sarà invisibile.",
	PageUseRemembered:          "Usa lo stesso certificato della richiesta precedente",
	PageRememberedHolder:       "%s: la pagina ha chiesto di conservarlo finché dura la connessione.",
	PageListening:              "In attesa che la pagina si colleghi a trebaruna su questo computer (porta %d)…",
	PageNextRequest:            "In attesa della prossima richiesta della pagina…",
	PageSessionClosed:          "La pagina ha chiuso la connessione con trebaruna.",
	PageLocalTLSMissing:        "Questa pagina comunica con trebaruna attraverso un canale cifrato su questo computer, che richiede il certificato locale di trebaruna. Si installa solo per il tuo utente: la sua radice non conserva la chiave privata e vale solo per 127.0.0.1.",
	PageInstallLocalTLS:        "Installa il certificato locale",
	MenuLocalChannel:           "Canale locale per i siti…",
	LocalChannelExplain:        "I siti che usano AutoFirma parlano con il programma attraverso un canale cifrato su questo computer. Perché il browser lo accetti, trebaruna installa per il tuo utente (Firefox e Chromium) una radice che vale solo per 127.0.0.1 e la cui chiave privata viene distrutta alla creazione: non può firmare nessun altro certificato.",
	LocalChannelInstalled:      "Installato per il tuo utente.",
	LocalChannelNotInstalled:   "Non installato.",
	LocalChannelRemove:         "Rimuovi",
	PageRejected:               "La pagina non accetta quel certificato (%s). Scegline un altro.",
	PageApprove:                "Firma e invia",
	PageApproveCertificate:     "Invia il certificato",
	PageApproveSave:            "Salva",
	PageDecline:                "Rifiuta",
	PageClose:                  "Chiudi",
	PageSaveTo:                 "Salva in…",
	PageDocument:               "Documento da firmare…",
	PageWorking:                "In corso; la risposta andrà a %s…",
	PageDone:                   "Fatto: la risposta è arrivata a %s.",
	PageDeclined:               "Hai rifiutato la richiesta; la pagina lo sa.",
	PageFailed:                 "Non completato: %s",
	MissingSaveTo:              "Scegli dove salvare.",
	PageKeyTitle:               "Con quale certificato",
	MenuCard:                   "Carta",
	MenuChangePIN:              "Cambia il PIN…",
	MenuUnlockPIN:              "Sblocca con il PUK…",
	MenuChangePUK:              "Cambia il PUK…",
	ChangePUKTitle:             "Cambia il PUK",
	ChangePUKHint:              "Scrivi il PUK attuale e quello nuovo due volte. Se sbagli il PUK, la carta conta un tentativo; esauriti, solo chi l'ha emessa può sbloccarla.",
	NewPUKLabel:                "Nuovo PUK",
	RepeatPUKLabel:             "Ripeti il nuovo PUK",
	ChangePUKButton:            "Cambia il PUK",
	PUKChanged:                 "PUK cambiato: la carta ora accetta quello nuovo.",
	CurrentPUKLabel:            "PUK attuale",
	ChangePINTitle:             "Cambia il PIN della carta",
	UnlockPINTitle:             "Sblocca la carta con il PUK",
	ChangePINHint:              "La carta controlla il PIN attuale una sola volta: se è errato, consuma uno dei suoi pochi tentativi.",
	UnlockPINHint:              "Il PUK si trova nella busta della carta, insieme al PIN. Serve anche se hai dimenticato il PIN. Anche i suoi tentativi sono pochi: se si blocca, solo l'emittente può sbloccare la carta.",
	PINDialogCard:              "Carta «%s».",
	PINDialogOnlyCard:          "La carta nel lettore.",
	CurrentPINLabel:            "PIN attuale",
	PUKLabel:                   "PUK",
	NewPINLabel:                "Nuovo PIN",
	RepeatPINLabel:             "Ripeti il nuovo PIN",
	ChangePINButton:            "Cambia il PIN",
	UnlockPINButton:            "Sblocca",
	CancelButton:               "Annulla",
	TalkingToCard:              "Comunicazione con la carta…",
	PINChanged:                 "PIN cambiato: la carta accetta già quello nuovo.",
	CardUnlocked:               "Carta sbloccata: il nuovo PIN funziona già.",
	PINMismatch:                "I due nuovi PIN non coincidono.",
	MissingPUK:                 "Scrivi il PUK della carta.",
	WrongPUK:                   "La carta ha rifiutato il PUK. Non è cambiato nulla.",
	WrongPUKFinalTry:           "La carta ha rifiutato il PUK. Resta un solo tentativo: un altro errore lo bloccherà e solo l'emittente potrà sbloccare la carta.",
	WrongPUKNowLocked:          "La carta ha rifiutato il PUK e lo ha bloccato: solo l'emittente può sbloccarla.",
	PUKLocked:                  "Il PUK è bloccato: solo l'emittente della carta può sbloccarla.",
	NewPINRejected:             "La carta non accetta quel nuovo PIN.",
	NewPINTooShort:             "Il nuovo PIN è troppo corto: la carta ne chiede almeno %s caratteri.",
	NewPINTooLong:              "Il nuovo PIN è troppo lungo: la carta ne accetta al massimo %s caratteri.",
	MenuRequests:               "Richieste dalle pagine web…",
	MenuEncrypt:                "Cifra per altri…",
	MenuOpenEnvelope:           "Apri una busta cifrata…",
	EnvelopesTitle:             "Buste cifrate",
	EncryptSection:             "Cifra per altri",
	EncryptIntro:               "Potranno aprirlo solo le persone di cui aggiungi il certificato. Aggiungi il tuo se vuoi aprirlo anche tu.",
	RecipientsLabel:            "Destinatari",
	AddRecipient:               "Aggiungi certificato…",
	RemoveRecipient:            "Rimuovi",
	NoRecipients:               "Ancora nessun destinatario.",
	EncryptButton:              "Cifra",
	EncryptingMessage:          "Cifratura in corso…",
	EncryptedAs:                "Cifrato come %s. Possono aprirlo: %s.",
	MissingRecipient:           "Aggiungi il certificato di almeno un destinatario.",
	OpenSection:                "Apri una busta",
	ChooseEnvelope:             "Scegli busta (.p7e)…",
	EnvelopeHint:               "Un .p7e che ti hanno inviato cifrato per il tuo certificato.",
	OpensWith:                  "Si apre con il certificato scelto per firmare: %s.",
	NoKeyToOpen:                "Scegli il tuo certificato in Firma (passo 2) per aprire le buste.",
	GoToCertificate:            "Scegli certificato",
	OpenEnvelopeButton:         "Apri busta",
	OpeningMessage:             "Apertura in corso…",
	OpenedAs:                   "Aperto come %s (%s).",
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
	AboutCardsYes:              "Supporta smart card e token (PKCS#11).",
	AboutCardsNo:               "Questa build non supporta le smart card: è la versione statica senza cgo.",
	AboutRevision:              "Revisione del codice: %s",
	AboutDependencies:          "Dipendenze e licenze (%d)",
	InvisibleSignature:         "Firma invisibile (senza timbro sulla pagina)",
	InvisibleExplained:         "Firma invisibile: il PDF è firmato e ogni lettore lo mostra nel pannello delle firme, ma sulla pagina non compare alcun timbro.",
	FormatDetachedLabel:        "Firma separata .p7s (CAdES): il documento non viene modificato",
	ExtractButton:              "Estrai il documento firmato",
	ExtractedAs:                "Documento estratto in %s. L'estrazione non verifica nulla: la verifica è quella sopra.",
	ExtractDocumentsButton:     "Estrai i documenti del contenitore",
	ExtractedFolder:            "Documenti estratti in %s. L'estrazione non verifica nulla: la verifica è quella sopra.",
	ReportButton:               "Salva il rapporto…",
	ReportFileName:             "%s - rapporto.pdf",
	ReportSavedAs:              "Rapporto salvato in %s.",
	FormatCosignLabel:          "Aggiungi una firma parallela: firmi lo stesso documento degli altri",
	FormatCountersignLabel:     "Controfirma: firmi sopra le firme già presenti",
	FormatWrapLabel:            "Racchiudi in un'altra busta .p7m (modo tradizionale)",
	CountersignatureOf:         "Controfirma della firma %s",
	FormatEachLabel:            "Ognuno nel suo formato: PDF firmato, XML firmato, .p7m per gli altri",
	FormatASiCSLabel:           "Contenitore ASiC-S (.asics): il documento e la sua firma insieme",
	FormatASiCELabel:           "Un contenitore ASiC-E con tutti (.asice), sotto un'unica firma",
	FormatFacturaELabel:        "Fattura FacturaE: firma interna, con la politica FacturaE",
	InvoiceRoleLabel:           "Firmi la fattura come",
	InvoiceRoleIssuer:          "emittente (emisor)",
	InvoiceRoleReceiver:        "destinatario (receptor)",
	InvoiceRoleThird:           "terzo (tercero)",
	PolicyLabel:                "Politica di firma dichiarata",
	PolicyNoneLabel:            "Nessuna",
	PolicyAGELabel:             "AGE 1.9 (Amministrazione statale spagnola)",
	PolicyAGE18Label:           "AGE 1.8",
	PolicyFacturaELabel:        "FacturaE 3.1",
	PolicyFacturaE30Label:      "FacturaE 3.0",
	PolicyHint:                 "Solo se la sede o il destinatario lo chiedono: la firma dichiara di seguire quella politica.",
	InvoiceDetected:            "È una fattura FacturaE: si firma all'interno, con la politica FacturaE e il tuo ruolo.",
	PolicyNotForFormat:         "Questa politica non si può dichiarare in questo formato.",
	InvoiceRoleMissing:         "Una fattura FacturaE si firma con la sua politica e come emittente, destinatario o terzo.",
	BatchTitle:                 "%d documenti",
	BatchSeal:                  "In un lotto, ogni PDF riceve il timbro nell'angolo in basso a destra della prima pagina.",
	BatchProgress:              "Firma %d di %d…",
	BatchDone:                  "Firmati %d di %d.",
	MenuSignFolder:             "Firma una cartella…",
	PreviewApproximate:         "È un abbozzo di trebaruna: il testo usa un altro carattere. Con poppler (pdftoppm) installato vedrai la pagina esatta.",
	PreviousPage:               "Pagina precedente",
	NextPage:                   "Pagina successiva",
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
	SealHint:                   "Click the page to place the seal, drag it to move it and pull its corner to enlarge it. With the keyboard, the arrow keys nudge it and + and − enlarge or shrink it.",
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
	KeyFromFile:                "File",
	KeyFromCard:                "Smart card",
	KeyFromFirefox:             "Firefox",
	KeyFromRemote:              "Remote service",
	RemoteAddressLabel:         "Service address (CSC)",
	RemoteUserLabel:            "User",
	RemotePasswordLabel:        "Password",
	RemoteClientLabel:          "Client id for signing in from the browser (OAuth2)",
	RemoteAccountHint:          "With a user and password, or with the id the provider gives trebaruna to sign in and authorise in your browser. The document stays here: only its hash travels.",
	RemoteOTPLabel:             "One-time code (if the service asks)",
	SearchRemote:               "Find credentials",
	NoRemoteCredentials:        "Type the service's address and how to sign in, then press “Find credentials”.",
	RemotePINPlaceholder:       "Remote signature PIN (if asked)",
	RemoteWhere:                "Kept by %s: it signs there; only the document's hash leaves this computer.",
	MissingService:             "Type the remote signing service's address.",
	FirefoxWhere:               "In Firefox's certificate store: used there, never exported.",
	FirefoxPasswordPlaceholder: "Firefox primary password",
	NoFirefoxCertificates:      "Firefox holds no certificate with its key. Import it in Firefox (Settings, Privacy & Security, View Certificates) or choose another source.",
	SearchCards:                "Look for cards",
	CardsSearching:             "Looking for cards in the readers…",
	NoCards:                    "No card with certificates is in the readers. Insert the card and press “Look for cards”.",
	CardPlaceholder:            "Choose the card's certificate",
	CardSigningRole:            "for signing",
	CardOtherRole:              "other use",
	CardWhere:                  "On the card “%s”, %s.",
	PINPlaceholder:             "Card PIN",
	PINPadHint:                 "This reader asks for the PIN on its own keypad when you sign.",
	PINCountLow:                "A wrong PIN has already been entered: few attempts are left before the card locks.",
	PINFinalTry:                "One attempt left: one more wrong PIN locks the card.",
	CardLocked:                 "The card is locked: unlock it with its PUK.",
	PINExpired:                 "The card asks for its PIN to be changed before it signs.",
	MissingPIN:                 "Type the card's PIN.",
	WrongPIN:                   "The card refused the PIN. Nothing was signed.",
	WrongPINFinalTry:           "The card refused the PIN. One attempt left: one more mistake locks it.",
	WrongPINNowLocked:          "The card refused the PIN and is now locked: unlock it with its PUK.",
	BatchNotTried:              "not tried, so no other PIN attempt was spent",
	FormatPAdESLabel:           "Signed PDF (PAdES): opens in any reader",
	FormatCAdESLabel:           ".p7m envelope (CAdES): what some offices require",
	FormatXAdESLabel:           "Signed XML (XAdES)",
	FormatODFLabel:             "LibreOffice document signed inside (ODF)",
	FormatOOXMLLabel:           "Office document signed inside (OOXML)",
	RubricLabel:                "Handwritten signature (optional)",
	ChooseRubric:               "Choose the signature image…",
	RubricHint:                 "A PNG or JPEG of your handwritten signature. It goes in the seal next to the certificate data, never alone.",
	RemoveRubric:               "Remove the handwritten signature",
	RubricInvalid:              "That image cannot be a handwritten signature: it must be a PNG or JPEG of at most 4 MiB and 4096 pixels a side.",
	FormatOnlyCAdES:            "This kind of file is signed inside a .p7m envelope (CAdES).",
	SealOnPagePane:             "The seal goes where you see it on the page to the right.",
	FormFieldLabel:             "Form's signature field",
	FormFieldNone:              "None: place the seal on the page",
	FormFieldOption:            "%s (page %d)",
	FormFieldsOffered:          "This PDF has fields reserved for signatures: choose one for the seal to go in it.",
	FormFieldSealHint:          "The form reserves this box for the signature: the seal goes here and does not move.",
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
	PageTitle:                  "A web page asks for your signature",
	PageSite:                   "The answer goes to %s.",
	PageAppName:                "The page calls itself “%s”.",
	PageOpSign:                 "Sign a document",
	PageOpCosign:               "Add your signature to a signed document",
	PageOpCountersign:          "Counter-sign the signatures of a document",
	PageOpSignAndSave:          "Sign a document and save it",
	PageOpSelectCert:           "Give it your certificate, signing nothing",
	PageOpSave:                 "Save a file on your computer",
	PageOpBatch:                "Sign %d documents",
	PageOpBatchOne:             "Sign 1 document",
	PageFormat:                 "Format: %s",
	PagePolicy:                 "The signature will declare the policy %s",
	PageRoles:                  "The signature will claim the role %s",
	PagePlace:                  "The signature will declare the place %s",
	PageData:                   "Data: %d bytes, SHA-256 fingerprint %s",
	PageDataURL:                "The data will be downloaded from %s if you approve.",
	PageChooseFile:             "The page sends no document: choose which one to sign.",
	PageFilters:                "It accepts only certificates matching: %s",
	PageWarnDES:                "The answer travels to the site encrypted with single DES and an 8-digit key: anyone who sees it can read it.",
	PageWarnDownload:           "The data will be downloaded from %s when you approve.",
	PageWarnBatch:              "The documents stay on the site: you sign what its server prepares from them, which trebaruna cannot show you.",
	PageWarnFilters:            "The page sets certificate conditions trebaruna does not understand; no certificate meets them.",
	PageWarnTriphase:           "The signature is prepared by the site's server (%s): you sign what that server computes, which trebaruna cannot show you.",
	PageWarnBare:               "A bare signature (NONE) records nothing of what it signs: if these bytes are the signed part of another signature, you sign whatever that one covers, which trebaruna cannot show you.",
	PageWarnDigest:             "The page sends only the %s digest of a document, %s, not the document: trebaruna cannot show it; if you have the document, compare its digest with this one.",
	PageWarnReferenced:         "The signature covers documents trebaruna does not see, only their address and digest: %s. Compare the digests with the documents' if you have them.",
	PageSealTitle:              "Place the seal on the page: drag it or draw its box. The page asked for a visible signature.",
	PageSealOptional:           "Add a visible seal",
	PageWarnSealLater:          "The page asks for a visible seal, but the document is fetched only after you approve: the signature will be invisible.",
	PageUseRemembered:          "Use the same certificate as in the previous request",
	PageRememberedHolder:       "%s: the page asked to keep it while the connection lasts.",
	PageListening:              "Waiting for the page to connect to trebaruna on this computer (port %d)…",
	PageNextRequest:            "Waiting for the page's next request…",
	PageSessionClosed:          "The page closed its connection to trebaruna.",
	PageLocalTLSMissing:        "This page talks to trebaruna over an encrypted channel on this computer, which needs trebaruna's local certificate. It is installed for your user only: its root keeps no private key and is valid for 127.0.0.1 alone.",
	PageInstallLocalTLS:        "Install the local certificate",
	MenuLocalChannel:           "Local channel for sites…",
	LocalChannelExplain:        "Sites that use AutoFirma talk to the program over an encrypted channel on this computer. For the browser to accept it, trebaruna installs for your user (Firefox and Chromium) a root valid for 127.0.0.1 alone, whose private key is destroyed when it is made: it cannot sign any other certificate.",
	LocalChannelInstalled:      "Installed for your user.",
	LocalChannelNotInstalled:   "Not installed.",
	LocalChannelRemove:         "Remove",
	PageRejected:               "The page does not accept that certificate (%s). Choose another.",
	PageApprove:                "Sign and send",
	PageApproveCertificate:     "Send the certificate",
	PageApproveSave:            "Save",
	PageDecline:                "Decline",
	PageClose:                  "Close",
	PageSaveTo:                 "Save to…",
	PageDocument:               "Document to sign…",
	PageWorking:                "Working; the answer goes to %s…",
	PageDone:                   "Done: the answer reached %s.",
	PageDeclined:               "You declined the request; the page knows.",
	PageFailed:                 "Not completed: %s",
	MissingSaveTo:              "Choose where to save.",
	PageKeyTitle:               "With which certificate",
	MenuCard:                   "Card",
	MenuChangePIN:              "Change the PIN…",
	MenuUnlockPIN:              "Unlock with the PUK…",
	MenuChangePUK:              "Change the PUK…",
	ChangePUKTitle:             "Change the PUK",
	ChangePUKHint:              "Type the current PUK and the new one twice. A wrong PUK costs one of the card's attempts; once they run out, only its issuer can unlock it.",
	NewPUKLabel:                "New PUK",
	RepeatPUKLabel:             "Repeat the new PUK",
	ChangePUKButton:            "Change the PUK",
	PUKChanged:                 "PUK changed: the card now takes the new one.",
	CurrentPUKLabel:            "Current PUK",
	ChangePINTitle:             "Change the card PIN",
	UnlockPINTitle:             "Unlock the card with the PUK",
	ChangePINHint:              "The card checks the current PIN once: a wrong one spends one of its few attempts.",
	UnlockPINHint:              "The PUK comes in the card's envelope, with the PIN. It also helps if you forgot the PIN. It has few attempts too: once it locks, only the issuer can unlock the card.",
	PINDialogCard:              "Card “%s”.",
	PINDialogOnlyCard:          "The card in the reader.",
	CurrentPINLabel:            "Current PIN",
	PUKLabel:                   "PUK",
	NewPINLabel:                "New PIN",
	RepeatPINLabel:             "Repeat the new PIN",
	ChangePINButton:            "Change the PIN",
	UnlockPINButton:            "Unlock",
	CancelButton:               "Cancel",
	TalkingToCard:              "Talking to the card…",
	PINChanged:                 "PIN changed: the card now takes the new one.",
	CardUnlocked:               "Card unlocked: the new PIN works now.",
	PINMismatch:                "The two new PINs differ.",
	MissingPUK:                 "Type the card's PUK.",
	WrongPUK:                   "The card refused the PUK. Nothing changed.",
	WrongPUKFinalTry:           "The card refused the PUK. One attempt left: one more mistake locks it, and only the issuer can unlock the card.",
	WrongPUKNowLocked:          "The card refused the PUK and locked it: only the issuer can unlock the card.",
	PUKLocked:                  "The PUK is locked: only the card's issuer can unlock it.",
	NewPINRejected:             "The card does not take that new PIN.",
	NewPINTooShort:             "The new PIN is too short: the card wants at least %s characters.",
	NewPINTooLong:              "The new PIN is too long: the card takes at most %s characters.",
	MenuRequests:               "Requests from web pages…",
	MenuEncrypt:                "Encrypt for others…",
	MenuOpenEnvelope:           "Open an encrypted envelope…",
	EnvelopesTitle:             "Encrypted envelopes",
	EncryptSection:             "Encrypt for others",
	EncryptIntro:               "Only the people whose certificates you add can open it. Add your own if you want to open it too.",
	RecipientsLabel:            "Recipients",
	AddRecipient:               "Add certificate…",
	RemoveRecipient:            "Remove",
	NoRecipients:               "No recipients yet.",
	EncryptButton:              "Encrypt",
	EncryptingMessage:          "Encrypting…",
	EncryptedAs:                "Encrypted as %s. It opens for: %s.",
	MissingRecipient:           "Add the certificate of at least one recipient.",
	OpenSection:                "Open an envelope",
	ChooseEnvelope:             "Choose envelope (.p7e)…",
	EnvelopeHint:               "A .p7e someone sent you, encrypted for your certificate.",
	OpensWith:                  "It opens with the certificate chosen to sign: %s.",
	NoKeyToOpen:                "Choose your certificate under Sign (step 2) to open envelopes.",
	GoToCertificate:            "Choose certificate",
	OpenEnvelopeButton:         "Open envelope",
	OpeningMessage:             "Opening…",
	OpenedAs:                   "Opened as %s (%s).",
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
	AboutCardsYes:              "Supports smartcards and tokens (PKCS#11).",
	AboutCardsNo:               "This build does not support smartcards: it is the static build without cgo.",
	AboutRevision:              "Source revision: %s",
	AboutDependencies:          "Dependencies and licences (%d)",
	InvisibleSignature:         "Invisible signature (no seal on the page)",
	InvisibleExplained:         "Invisible signature: the PDF is signed and every reader shows it in its signature panel, but no seal is drawn on the page.",
	FormatDetachedLabel:        "Detached .p7s signature (CAdES): the document is left untouched",
	ExtractButton:              "Extract the signed document",
	ExtractedAs:                "Document extracted to %s. Extraction checks nothing: the check is the one above.",
	ExtractDocumentsButton:     "Extract the container's documents",
	ExtractedFolder:            "Documents extracted to %s. Extracting checks nothing: the check is the one above.",
	ReportButton:               "Save report…",
	ReportFileName:             "%s - report.pdf",
	ReportSavedAs:              "Report saved to %s.",
	FormatCosignLabel:          "Add a parallel signature: you sign what the others signed",
	FormatCountersignLabel:     "Counter-sign: you sign over the signatures already there",
	FormatWrapLabel:            "Wrap in another .p7m envelope (the old way)",
	CountersignatureOf:         "Counter-signature of signature %s",
	FormatEachLabel:            "Each in its own format: signed PDF, signed XML, .p7m for the rest",
	FormatASiCSLabel:           "ASiC-S container (.asics): the document and its signature together",
	FormatASiCELabel:           "One ASiC-E container with them all (.asice), under one signature",
	FormatFacturaELabel:        "FacturaE invoice: signed inside, with FacturaE's policy",
	InvoiceRoleLabel:           "You sign the invoice as",
	InvoiceRoleIssuer:          "issuer (emisor)",
	InvoiceRoleReceiver:        "recipient (receptor)",
	InvoiceRoleThird:           "third party (tercero)",
	PolicyLabel:                "Signature policy it declares",
	PolicyNoneLabel:            "None",
	PolicyAGELabel:             "AGE 1.9 (Spanish State Administration)",
	PolicyAGE18Label:           "AGE 1.8",
	PolicyFacturaELabel:        "FacturaE 3.1",
	PolicyFacturaE30Label:      "FacturaE 3.0",
	PolicyHint:                 "Only when the office or the recipient asks: the signature declares it follows that policy.",
	InvoiceDetected:            "This is a FacturaE invoice: it is signed inside, with FacturaE's policy and your role in it.",
	PolicyNotForFormat:         "That policy cannot be declared in this format.",
	InvoiceRoleMissing:         "A FacturaE invoice is signed with its policy, as issuer, recipient or third party.",
	BatchTitle:                 "%d documents",
	BatchSeal:                  "In a batch, every PDF gets the seal in the bottom-right corner of its first page.",
	BatchProgress:              "Signing %d of %d…",
	BatchDone:                  "Signed %d of %d.",
	MenuSignFolder:             "Sign a folder…",
	PreviewApproximate:         "This is trebaruna's sketch: the text is in another typeface. With poppler (pdftoppm) installed you see the exact page.",
	PreviousPage:               "Previous page",
	NextPage:                   "Next page",
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
