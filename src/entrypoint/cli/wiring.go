package cli

import (
	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationapp "codeberg.org/simplicer/trebaruna/src/verification/application"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// Signing wires the signing use case with every format trebaruna writes:
// PAdES, CAdES, XAdES and XMLDSig, ASiC containers, OpenDocument and Office
// Open XML. The command line, the local API and the desktop sign through
// the same wiring, so a format added here is available to all of them.
func Signing(timestamper infrastructure.Timestamper) *application.SignDocument {
	xadesSigner := infrastructure.NewXadesSigner(timestamper)
	return application.NewSignDocument(
		infrastructure.DiskStore{},
		application.SystemClock{},
		infrastructure.CertificateInspector{},
		infrastructure.NewCadesSigner(timestamper),
		infrastructure.NewPadesSigner(timestamper),
		xadesSigner,
	).WithContainers(infrastructure.AsicContainers{}).
		WithOdf(infrastructure.NewOdfSigner(xadesSigner)).
		WithOoxml(infrastructure.NewOoxmlSigner(xadesSigner))
}

// SigningAsPDF wires signing a text, spreadsheet or presentation as the PDF
// LibreOffice prints of it.
func SigningAsPDF(timestamper infrastructure.Timestamper) *application.SignAsPDF {
	return application.NewSignAsPDF(infrastructure.LibreOffice{}, Signing(timestamper))
}

// Conversion wires turning such a document into a PDF beside it.
func Conversion() *application.ConvertDocument {
	return application.NewConvertDocument(infrastructure.LibreOffice{}, infrastructure.DiskStore{})
}

// Verification wires the verification use case with every format trebaruna
// reads, over the PDF verifier given (whose revocation checks the caller
// decides).
func Verification(pdf *verificationinfra.PDFVerifier) *verificationapp.VerifyDocument {
	return verificationapp.NewVerifyDocument(
		pdf,
		verificationinfra.NewCadesVerifier(),
		verificationinfra.NewCachedTrustProvider(),
		systemClock{},
	).WithXades(verificationinfra.NewXadesVerifier()).
		WithAsic(verificationinfra.NewAsicVerifier(verificationinfra.NewCadesVerifier(), verificationinfra.NewXadesVerifier())).
		WithOdf(verificationinfra.NewOdfVerifier(verificationinfra.NewXadesVerifier())).
		WithOoxml(verificationinfra.NewOoxmlVerifier(verificationinfra.NewXadesVerifier()))
}
