package domain

import "fmt"

// FailureCode is an AutoFirma error code, answered as "SAF_NN: text" (B.3).
type FailureCode int

const (
	CannotReadData         FailureCode = 0
	NullURI                FailureCode = 1
	UnsupportedProtocol    FailureCode = 2
	Params                 FailureCode = 3
	UnsupportedOperation   FailureCode = 4
	CannotSaveData         FailureCode = 5
	UnsupportedFormat      FailureCode = 6
	CannotAccessKeystore   FailureCode = 8
	SignatureFailed        FailureCode = 9
	SendingResult          FailureCode = 11
	EncryptingData         FailureCode = 12
	LocalAccessBlocked     FailureCode = 13
	DecryptingData         FailureCode = 15
	RecoveringData         FailureCode = 16
	UnknownSigner          FailureCode = 17
	NoCertificatesKeystore FailureCode = 19
	UnsupportedProcedure   FailureCode = 21
	InvalidPolicy          FailureCode = 23
	ContactBatchService    FailureCode = 26
	BatchSignature         FailureCode = 27
	InvalidPDF             FailureCode = 28
	InvalidXML             FailureCode = 29
	InvalidData            FailureCode = 30
	NoSignData             FailureCode = 31
	InvalidFacturaE        FailureCode = 38
	InvalidSignature       FailureCode = 39
	MinimumVersion         FailureCode = 41
	CannotOpenSocket       FailureCode = 45
	ConfirmationNeeded     FailureCode = 50
	IncompatibleKeyType    FailureCode = 51
	LockedKeystore         FailureCode = 52
)

// failureTexts are AutoFirma 1.9's Spanish messages (protocolmessages
// properties), which pages show as they come.
var failureTexts = map[FailureCode]string{
	0:  "No se han podido leer los datos a firmar",
	1:  "La URL recibida es nula",
	2:  "Protocolo no soportado",
	3:  "Error en los parámetros de entrada",
	4:  "Operación no soportada. Compruebe que dispone de la última versión de Autofirma.",
	5:  "No se ha podido guardar los datos",
	6:  "Formato de firma no soportado",
	7:  "No se ha podido determinar el almacén de claves a utilizar",
	8:  "Error accediendo al almacén de claves y certificados",
	9:  "Error realizando la firma electrónica",
	10: "No hay certificados de firma instalados en el sistema",
	11: "Error en el envio del resultado de la operación.",
	12: "Error en el cifrado de los datos a enviar",
	13: "Se ha pedido acceso a una dirección local, pero por seguridad se ha bloqueado el acceso",
	15: "Error en el descifrado de los datos",
	16: "Error al recuperar los datos del servidor intermedio",
	17: "Los datos proporcionados no son una firma electrónica reconocida",
	18: "Error al descodificar el certificado de firma",
	19: "No hay ningun certificado válido en su almacén. Compruebe las fechas de caducidad e instale un certificado válido.",
	20: "Error en el procesado del lote de firma.",
	21: "La versión de Autofirma instalada no es compatible con este trámite.\nActualice a la última versión disponible.",
	23: "Se ha establecido una política de firma no válida o parámetros no compatibles con ella.",
	25: "Error en la lectura de los datos a cargar.",
	26: "Error en la comunicación con el servicio de firma de lotes.",
	27: "El servicio informó de un error durante la firma del lote.",
	28: "El fichero no es un PDF o es un PDF no soportado.",
	29: "Las firmas XAdES Enveloped solo pueden realizarse sobre datos XML.",
	30: "El formato de los datos a firmar no es adecuado para el tipo de firma seleccionado.",
	31: "Los datos introducidos no se corresponden con un objeto de firma.",
	32: "La factura ya tiene una firma electrónica y no admite firmas adicionales.",
	38: "El archivo que intenta firmar no es una factura electrónica reconocida.",
	39: "La firma de entrada no es válida.",
	40: "Error al recuperar el documento",
	41: "El uso de este trámite web requiere una versión más reciente de Autofirma.\nActualice a la última versión disponible.",
	45: "No se pudo abrir un socket para la comunicación con la aplicación",
	50: "La operación puede generar firmas no validas, por lo que no se puede continuar sin confirmacion de usuario.",
	51: "El tipo de clave del certificado no está soportado.",
	52: "El almacén de claves esta bloqueado. Siga las instrucciones del proveedor del almacén o tarjeta para desbloquearlo.",
}

// Failure is an error the page receives as "SAF_NN: text".
type Failure struct {
	Code FailureCode
	// Cause is the underlying reason, which signature failures carry in
	// place of the generic text (B.3); empty means the generic text.
	Cause string
}

// Error renders the failure for logs.
func (f Failure) Error() string {
	if f.Cause != "" {
		return fmt.Sprintf("SAF_%02d: %s (%s)", f.Code, failureTexts[f.Code], f.Cause)
	}
	return fmt.Sprintf("SAF_%02d: %s", f.Code, failureTexts[f.Code])
}

// Answer is what the page receives: the generic text, except for the
// signature failures, which AutoFirma answers with their cause (B.3).
func (f Failure) Answer() string {
	switch f.Code {
	case CannotAccessKeystore, SignatureFailed, InvalidPolicy, ConfirmationNeeded, IncompatibleKeyType, LockedKeystore:
		if f.Cause != "" {
			return fmt.Sprintf("SAF_%02d: %s", f.Code, f.Cause)
		}
	}
	return fmt.Sprintf("SAF_%02d: %s", f.Code, failureTexts[f.Code])
}

// CancelAnswer is the literal answer for a person who said no (B.2).
const CancelAnswer = "CANCEL"
