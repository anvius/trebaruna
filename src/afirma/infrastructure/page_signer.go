// Package infrastructure adapts afirma:// requests to trebaruna's signers,
// keys and network, and to the sites' intermediate servers.
package infrastructure

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	signapp "codeberg.org/simplicer/trebaruna/src/signing/application"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
	signinfra "codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// NativePageSigner signs with trebaruna's own CAdES, PAdES and XAdES signers,
// reading AutoFirma's extraParams (A.7) for what they cover. What trebaruna
// does not do yet is refused by name rather than signed some other way.
type NativePageSigner struct {
	cades signapp.CadesSigner
	pades signapp.PadesSigner
	xades signapp.XadesSigner
	odf   signapp.OdfSigner
}

// NewNativePageSigner wires the signers with the RFC 3161 client.
func NewNativePageSigner() NativePageSigner {
	timestamps := signinfra.NewRfc3161Timestamper()
	xades := signinfra.NewXadesSigner(timestamps)
	return NativePageSigner{
		cades: signinfra.NewCadesSigner(timestamps),
		pades: signinfra.NewPadesSigner(timestamps),
		xades: xades,
		odf:   signinfra.NewOdfSigner(xades),
	}
}

// unsupportedProperties are extraParams that change what is signed and that
// trebaruna does not honour yet; signing without them would hand the page a
// signature it did not ask for.
var unsupportedProperties = map[string]string{
	"precalculatedHashAlgorithm": "signing a digest the page computed",
	"useManifest":                "XAdES manifests",
}

// Sign makes the signature the page asked for.
func (s NativePageSigner) Sign(ctx context.Context, request application.PageSignature) (application.Signed, error) {
	for property, what := range unsupportedProperties {
		if request.Properties[property] != "" {
			return application.Signed{}, domain.Failure{Code: domain.UnsupportedOperation, Cause: what + " are not supported yet"}
		}
	}
	family := request.Format.Family
	if request.Format.Auto() {
		family = detectFamily(request.Crypto, request.Data)
		request.Format.Family = family
	}
	level, tsa := signing.BES, request.Properties["tsaURL"]
	if tsa != "" {
		level = signing.T
	}
	request, policy, err := withPolicy(request, family)
	if err != nil {
		return application.Signed{}, err
	}

	var signature []byte
	switch {
	case request.Format.Packaging == "asic-s":
		signature, err = s.signASiCS(ctx, request, family, level, tsa, policy)
	case family == "cades":
		signature, err = s.signCades(ctx, request, level, tsa, policy)
	case family == "pades" && !policy.IsZero():
		return application.Signed{}, domain.Failure{Code: domain.UnsupportedOperation, Cause: "PAdES signatures with a policy are not supported yet"}
	case family == "pades":
		signature, err = s.signPades(ctx, request, level, tsa)
	case family == "xades", family == "facturae", family == "xmldsig":
		signature, err = s.signXades(ctx, request, level, tsa, policy)
	case family == "odf":
		signature, err = s.signOdf(ctx, request, level, tsa, policy)
	default:
		return application.Signed{}, domain.Failure{Code: domain.UnknownSigner}
	}
	if err != nil {
		return application.Signed{}, err
	}
	certificate, err := KeyCertificates{}.Certificate(request.Key)
	if err != nil {
		return application.Signed{}, domain.Failure{Code: domain.CannotAccessKeystore, Cause: err.Error()}
	}
	return application.Signed{Certificate: certificate, Signature: signature}, nil
}

// detectFamily applies auto (A.9): PDF → PAdES, a FacturaE invoice →
// FacturaE, other XML → XAdES, anything else CAdES; for co- and
// counter-signatures, the input signature decides.
func detectFamily(crypto domain.Operation, data []byte) string {
	trimmed := bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(data, []byte("%PDF")):
		return "pades"
	case crypto == domain.Sign && signing.IsFacturaEInvoice(data):
		return "facturae"
	case crypto == domain.Sign && bytes.HasPrefix(trimmed, []byte("<")):
		return "xades"
	case crypto == domain.Sign:
		return "cades"
	case len(trimmed) > 0 && trimmed[0] == 0x30:
		return "cades"
	}
	return ""
}

// signCades signs, co-signs or counter-signs CMS; mode=explicit leaves the
// data out of the signature.
func (s NativePageSigner) signCades(ctx context.Context, request application.PageSignature, level signing.Level, tsa string,
	policy signing.SignaturePolicy) ([]byte, error) {
	if request.Crypto != domain.Sign && !isCMS(request.Data) {
		return nil, domain.Failure{Code: domain.NoSignData}
	}
	cades := signapp.CadesRequest{Content: request.Data, Signer: request.Key, Level: level, TimestampURL: tsa, Policy: policy}
	switch request.Crypto {
	case domain.Sign:
		cades.Detached = strings.EqualFold(request.Properties["mode"], "explicit")
	case domain.Cosign:
		cades.Cosign = true
	case domain.Countersign:
		cades.Countersign = domain.CounterTarget(request.Properties)
	}
	signature, err := s.cades.SignCades(ctx, cades)
	if err != nil {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	return signature, nil
}

// signPades signs a PDF: invisibly, as AutoFirma does, unless the page gives
// the seal's place (signaturePage, signaturePositionOnPage…).
func (s NativePageSigner) signPades(ctx context.Context, request application.PageSignature, level signing.Level, tsa string) ([]byte, error) {
	if !bytes.HasPrefix(request.Data, []byte("%PDF")) {
		return nil, domain.Failure{Code: domain.InvalidPDF}
	}
	if request.Crypto == domain.Countersign {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "a PDF takes signatures, not counter-signatures"}
	}
	pades := signapp.PadesRequest{
		Content: request.Data, Signer: request.Key, Level: level, TimestampURL: tsa,
		Reason: request.Properties["signReason"], Location: request.Properties["signatureProductionCity"],
	}
	placement, placed, err := sealFrom(request.Properties)
	if err != nil {
		return nil, err
	}
	if placed {
		pades.Placements = []signing.SealPlacement{placement}
	}
	signature, err := s.pades.SignPades(ctx, pades)
	if err != nil {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	return signature, nil
}

// sealFrom reads the seal box AutoFirma's PDF parameters give.
func sealFrom(properties map[string]string) (signing.SealPlacement, bool, error) {
	keys := []string{"signaturePositionOnPageLowerLeftX", "signaturePositionOnPageLowerLeftY",
		"signaturePositionOnPageUpperRightX", "signaturePositionOnPageUpperRightY"}
	var box [4]float64
	for index, key := range keys {
		value := strings.TrimSpace(properties[key])
		if value == "" {
			return signing.SealPlacement{}, false, nil
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return signing.SealPlacement{}, false, domain.Failure{Code: domain.Params, Cause: key}
		}
		box[index] = parsed
	}
	page := 1
	if text := strings.TrimSpace(properties["signaturePage"]); text != "" && text != "-1" && text != "0" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed < 1 {
			return signing.SealPlacement{}, false, domain.Failure{Code: domain.Params, Cause: "signaturePage"}
		}
		page = parsed
	}
	placement, err := signing.PlaceSeal(page, box[0], box[1], box[2], box[3])
	if err != nil {
		return signing.SealPlacement{}, false, domain.Failure{Code: domain.Params, Cause: err.Error()}
	}
	return placement, true, nil
}

// signXades signs XML enveloped, or anything enveloping; a FacturaE invoice
// always enveloped, claiming the issuer's role unless the page names another.
func (s NativePageSigner) signXades(ctx context.Context, request application.PageSignature, level signing.Level, tsa string,
	policy signing.SignaturePolicy) ([]byte, error) {
	if request.Crypto != domain.Sign {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "XAdES co- and counter-signatures are not supported yet"}
	}
	// AutoFirma's "XAdES Detached" keeps the data inside a new document, beside
	// the signature (AFIRMA/CONTENT), so the page receives one file.
	var packaging signing.XMLPackaging
	switch xadesPackaging(request) {
	case "enveloping":
		packaging = signing.XMLEnveloping
	case "detached":
		packaging = signing.XMLInternallyDetached
	case "enveloped":
		if !bytes.HasPrefix(bytes.TrimSpace(request.Data), []byte("<")) {
			return nil, domain.Failure{Code: domain.InvalidXML}
		}
		packaging = signing.XMLEnveloped
	default:
		return nil, domain.Failure{Code: domain.UnsupportedFormat, Cause: "XAdES " + xadesPackaging(request)}
	}
	// XMLDSig has no signed properties: AutoFirma leaves the roles out, and so
	// does this. A policy was refused before, a timestamp is refused here.
	plain := request.Format.Family == "xmldsig"
	if plain && level != signing.BES {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "XMLDSig signatures carry no timestamp; ask for XAdES"}
	}
	roles := claimedRoles(request.Properties)
	if plain {
		roles = nil
	}
	if policy.IsFacturaE() {
		if err := policy.AcceptsInvoice(request.Data); err != nil {
			return nil, domain.Failure{Code: domain.InvalidFacturaE, Cause: err.Error()}
		}
		var err error
		if roles, err = signing.FacturaERoles(roles); err != nil {
			return nil, domain.Failure{Code: domain.InvalidPolicy, Cause: err.Error()}
		}
	}
	signature, err := s.xades.SignXades(ctx, signapp.XadesRequest{Content: request.Data, Signer: request.Key, Level: level,
		Packaging: packaging, Plain: plain, TimestampURL: tsa, Policy: policy, ClaimedRoles: roles})
	if err != nil {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	return signature, nil
}

// xadesPackaging is the XAdES variant asked for: in the format's name
// ("XAdES Enveloping") or in the format property; FacturaE is enveloped, and
// nothing said is enveloping, AutoFirma's default (XAdESSigner).
func xadesPackaging(request application.PageSignature) string {
	if request.Format.Family == "facturae" {
		return "enveloped"
	}
	if request.Format.Packaging != "" {
		return request.Format.Packaging
	}
	variant := strings.ToLower(strings.TrimSpace(request.Properties["format"]))
	for _, family := range []string{"xades ", "xmldsig "} {
		variant = strings.TrimPrefix(variant, family)
	}
	if variant != "" {
		return variant
	}
	return "enveloping"
}

// claimedRoles reads signerClaimedRoles, several separated by "|".
func claimedRoles(properties map[string]string) []string {
	var roles []string
	for _, role := range strings.Split(properties["signerClaimedRoles"], "|") {
		if role = strings.TrimSpace(role); role != "" {
			roles = append(roles, role)
		}
	}
	return roles
}

// signOdf signs an OpenDocument file inside itself, as AutoFirma's ODF
// signer and LibreOffice do.
func (s NativePageSigner) signOdf(ctx context.Context, request application.PageSignature, level signing.Level, tsa string,
	policy signing.SignaturePolicy) ([]byte, error) {
	if request.Crypto != domain.Sign {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "an OpenDocument file takes more signatures by being signed again"}
	}
	signed, err := s.odf.SignOdf(ctx, signapp.XadesRequest{Content: request.Data, Signer: request.Key, Level: level,
		TimestampURL: tsa, Policy: policy, ClaimedRoles: claimedRoles(request.Properties)})
	switch {
	case errors.Is(err, signinfra.ErrNotOpenDocument):
		return nil, domain.Failure{Code: domain.InvalidData, Cause: err.Error()}
	case err != nil:
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	return signed, nil
}

// signASiCS packs the data and a detached signature into an ASiC-S
// container, as AutoFirma's CAdES-ASiC-S and XAdES-ASiC-S do: the data under
// the page's asicsFilename, or dataobject.<extension> from its content.
func (s NativePageSigner) signASiCS(ctx context.Context, request application.PageSignature, family string, level signing.Level, tsa string,
	policy signing.SignaturePolicy) ([]byte, error) {
	if request.Crypto != domain.Sign {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "signatures are not added to ASiC containers yet"}
	}
	name := request.Properties["asicsFilename"]
	if name == "" {
		name = "dataobject." + dataExtension(request.Data)
	}
	if strings.ContainsAny(name, `/\:`) || name == "." || name == ".." {
		return nil, domain.Failure{Code: domain.Params, Cause: "asicsFilename names a file, not a path"}
	}

	var signature []byte
	var err error
	format := signing.Cades
	switch family {
	case "cades":
		signature, err = s.cades.SignCades(ctx, signapp.CadesRequest{Content: request.Data, Signer: request.Key, Level: level,
			TimestampURL: tsa, Detached: true, Policy: policy})
	case "xades":
		format = signing.Xades
		signature, err = s.xades.SignXades(ctx, signapp.XadesRequest{Content: request.Data, Signer: request.Key, Level: level,
			TimestampURL: tsa, Packaging: signing.XMLDetached, DocumentName: name, InASiC: true, Policy: policy,
			ClaimedRoles: claimedRoles(request.Properties)})
	default:
		return nil, domain.Failure{Code: domain.UnsupportedFormat, Cause: request.Format.Name}
	}
	if err != nil {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	container, err := signinfra.AsicContainers{}.WriteContainer(signing.ASiCS, []signapp.ContainerEntry{
		{Name: name, Content: request.Data},
		{Name: signing.ASiCS.SignatureEntry(format), Content: signature},
	})
	if err != nil {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	return container, nil
}

// dataExtension names the data's kind from its content, as AutoFirma's
// MimeHelper does for an ASiC-S data object; bin when unknown.
func dataExtension(data []byte) string {
	if isXML(data) {
		return "xml"
	}
	switch kind := http.DetectContentType(data); {
	case strings.HasPrefix(kind, "application/pdf"):
		return "pdf"
	case strings.HasPrefix(kind, "text/xml"), strings.HasPrefix(kind, "application/xml"):
		return "xml"
	case strings.HasPrefix(kind, "text/plain"):
		return "txt"
	case strings.HasPrefix(kind, "image/png"):
		return "png"
	case strings.HasPrefix(kind, "image/jpeg"):
		return "jpg"
	case strings.HasPrefix(kind, "application/zip"):
		return "zip"
	}
	return "bin"
}

// isXML reports data that open with an XML element; content sniffing alone
// takes XML without a declaration for text.
func isXML(data []byte) bool {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("<")) {
		return false
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		if _, ok := token.(xml.StartElement); ok {
			return true
		}
	}
}

// isCMS reports a DER (or BER) SEQUENCE, the start of every CMS envelope.
func isCMS(data []byte) bool { return len(data) > 1 && data[0] == 0x30 }

// KeyCertificates reads the certificate of a key, from a file, a card or a
// store (selectcert and the signer's answer).
type KeyCertificates struct{}

// Certificate returns the DER of the key's certificate.
func (KeyCertificates) Certificate(key signing.Signer) ([]byte, error) {
	pair, err := signinfra.LoadKeyPair(key)
	if err != nil {
		return nil, err
	}
	defer pair.Close()
	if pair.Certificate == nil {
		return nil, fmt.Errorf("the key has no certificate")
	}
	return pair.Certificate.Raw, nil
}

// compile-time checks.
var (
	_ application.PageSigner        = NativePageSigner{}
	_ application.CertificateReader = KeyCertificates{}
)
