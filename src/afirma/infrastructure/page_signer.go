// Package infrastructure adapts afirma:// requests to trebaruna's signers,
// keys and network, and to the sites' intermediate servers.
package infrastructure

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// NativePageSigner signs with trebaruna's own CAdES, PAdES and XAdES signers,
// reading AutoFirma's extraParams (A.7) for what they cover. What trebaruna
// does not do yet is refused by name rather than signed some other way.
type NativePageSigner struct {
	cades signapp.CadesSigner
	pades signapp.PadesSigner
	xades signapp.XadesSigner
	odf   signapp.OdfSigner
	ooxml signapp.OoxmlSigner
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
		ooxml: signinfra.NewOoxmlSigner(xades),
	}
}

// Sign makes the signature the page asked for.
func (s NativePageSigner) Sign(ctx context.Context, request application.PageSignature) (application.Signed, error) {
	family := request.Format.Family
	if request.Format.Auto() {
		family = detectFamily(request.Crypto, request.Data)
		request.Format.Family = family
	}
	// A digest the page computed is signed in CAdES and in XAdES Externally
	// Detached; AutoFirma's NONE ignores the property and signs the bytes as
	// they are, and so does this.
	externally := family == "xades" && domain.ExternallyDetached(request.Properties)
	if request.Properties["precalculatedHashAlgorithm"] != "" && family != "cades" && family != "none" && !externally {
		return application.Signed{}, domain.Failure{Code: domain.UnsupportedOperation,
			Cause: "a digest the page computed is signed in CAdES and XAdES Externally Detached only"}
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
	case family == "pades":
		signature, err = s.signPades(ctx, request, level, tsa, policy)
	case family == "xades", family == "facturae", family == "xmldsig":
		signature, err = s.signXades(ctx, request, level, tsa, policy)
	case family == "odf", family == "ooxml":
		signature, err = s.signOffice(ctx, request, family, level, tsa, policy)
	case family == "none":
		signature, err = signBare(request)
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
// counter-signatures, the input signature decides: a CMS envelope, or a
// signed XML.
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
	case bytes.HasPrefix(trimmed, []byte("<")) && bytes.Contains(data, []byte(xmldsig.Namespace)):
		// A signed XML: its signatures are co- or counter-signed in XAdES.
		return "xades"
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
	if algorithm := request.Properties["precalculatedHashAlgorithm"]; algorithm != "" {
		digest, err := pageDigest(request, algorithm)
		if err != nil {
			return nil, err
		}
		cades.ContentDigest, cades.Detached = digest, true
	}
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

// pageDigest reads the data as the document's digest (AutoFirma's
// precalculatedHashAlgorithm): its algorithm must be the signature
// algorithm's, as one SignerInfo digests both the document and its
// attributes, and only a signature is made over it.
func pageDigest(request application.PageSignature, algorithm string) (signing.ContentDigest, error) {
	if request.Crypto != domain.Sign {
		return signing.ContentDigest{}, domain.Failure{Code: domain.UnsupportedOperation, Cause: "a digest is signed, not co- or counter-signed"}
	}
	digest, err := signing.NewContentDigest(algorithm, request.Data)
	if err != nil {
		return signing.ContentDigest{}, domain.Failure{Code: domain.Params, Cause: err.Error()}
	}
	if signed := domain.DigestOf(request.Algorithm); signed != digest.Algorithm() {
		return signing.ContentDigest{}, domain.Failure{Code: domain.Params,
			Cause: "the digest is " + digest.Algorithm() + " and the signature algorithm " + request.Algorithm}
	}
	return digest, nil
}

// signPades signs a PDF: invisibly, as AutoFirma does, unless the page gives
// the seal's place (signaturePage, signaturePositionOnPage…) or a form's
// field to sign in (signatureField).
func (s NativePageSigner) signPades(ctx context.Context, request application.PageSignature, level signing.Level, tsa string, policy signing.SignaturePolicy) ([]byte, error) {
	if !bytes.HasPrefix(request.Data, []byte("%PDF")) {
		return nil, domain.Failure{Code: domain.InvalidPDF}
	}
	if request.Crypto == domain.Countersign {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "a PDF takes signatures, not counter-signatures"}
	}
	// AutoFirma opens an encrypted PDF with ownerPassword, else userPassword.
	password := request.Properties["ownerPassword"]
	if password == "" {
		password = request.Properties["userPassword"]
	}
	pades := signapp.PadesRequest{
		Content: request.Data, Signer: request.Key, Level: level, TimestampURL: tsa, Password: password,
		Reason: request.Properties["signReason"], Location: request.Properties["signatureProductionCity"],
		Policy: policy,
	}
	// signatureField names the form's empty field to sign in, the seal in
	// its box; the position keys then do not apply.
	placement, placed, err := sealFrom(request.Properties)
	if err != nil {
		return nil, err
	}
	if pades.Field = strings.TrimSpace(request.Properties["signatureField"]); pades.Field == "" && placed {
		pades.Placements = []signing.SealPlacement{placement}
	}
	if pades.Field != "" || placed {
		if pades.Rubric, err = rubricFrom(request.Properties["signatureRubricImage"]); err != nil {
			return nil, err
		}
	}
	signature, err := s.pades.SignPades(ctx, pades)
	if err != nil {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	return signature, nil
}

// rubricFrom reads signatureRubricImage, the Base64 image AutoFirma draws
// in the seal; trebaruna draws it beside the certificate data (ADR-0012).
// As in AutoFirma it only counts with a seal box: without one the signature
// is invisible.
func rubricFrom(encoded string) (signing.Rubric, error) {
	if strings.TrimSpace(encoded) == "" {
		return signing.Rubric{}, nil
	}
	content, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		return signing.Rubric{}, domain.Failure{Code: domain.Params, Cause: "signatureRubricImage is not Base64"}
	}
	rubric, err := signing.NewRubric(content)
	if err != nil {
		return signing.Rubric{}, domain.Failure{Code: domain.Params, Cause: "signatureRubricImage: " + err.Error()}
	}
	return rubric, nil
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
	plain := request.Format.Family == "xmldsig"
	if request.Crypto == domain.Countersign {
		if plain {
			return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "an XMLDSig signature has no properties to hold a counter-signature"}
		}
		signature, err := s.xades.SignXades(ctx, signapp.XadesRequest{Content: request.Data, Signer: request.Key, Level: level,
			TimestampURL: tsa, Policy: policy, ClaimedRoles: domain.ClaimedRoles(request.Properties), Countersign: domain.CounterTarget(request.Properties),
			Place: productionPlace(request.Properties)})
		if err != nil {
			return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
		}
		return signature, nil
	}
	if request.Format.Family == "xades" && domain.ExternallyDetached(request.Properties) {
		return s.signReferenced(ctx, request, level, tsa, policy)
	}
	// AutoFirma's "XAdES Detached" keeps the data inside a new document, beside
	// the signature (AFIRMA/CONTENT), so the page receives one file. A
	// co-signature is the signed document signed again, enveloped: the new
	// signature leaves the others out.
	variant := xadesPackaging(request)
	if request.Crypto == domain.Cosign {
		variant = "enveloped"
	}
	var packaging signing.XMLPackaging
	switch variant {
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
		return nil, domain.Failure{Code: domain.UnsupportedFormat, Cause: "XAdES " + variant}
	}
	// XMLDSig has no signed properties: AutoFirma leaves the roles out, and so
	// does this. A policy was refused before, a timestamp is refused here.
	if plain && level != signing.BES {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "XMLDSig signatures carry no timestamp; ask for XAdES"}
	}
	roles := domain.ClaimedRoles(request.Properties)
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
	place := productionPlace(request.Properties)
	if plain {
		place = signing.ProductionPlace{}
	}
	signature, err := s.xades.SignXades(ctx, signapp.XadesRequest{Content: request.Data, Signer: request.Key, Level: level,
		Packaging: packaging, Plain: plain, TimestampURL: tsa, Policy: policy, ClaimedRoles: roles, Place: place})
	if err != nil {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	return signature, nil
}

// signReferenced makes AutoFirma's XAdES Externally Detached: a detached
// signature over documents named by address and signed by the digests the
// page gives, their references in a ds:Manifest with useManifest. Only a
// signature: there is nothing here to co- or counter-sign.
func (s NativePageSigner) signReferenced(ctx context.Context, request application.PageSignature, level signing.Level, tsa string,
	policy signing.SignaturePolicy) ([]byte, error) {
	if request.Crypto != domain.Sign {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "documents named by address are signed, not co- or counter-signed"}
	}
	documents, err := domain.References(request.Properties, request.Data)
	if err != nil {
		return nil, err
	}
	referenced := make([]signapp.ReferencedDocument, len(documents))
	for index, document := range documents {
		digest, err := signing.NewContentDigest(document.Algorithm, document.Digest)
		if err != nil {
			return nil, domain.Failure{Code: domain.Params, Cause: document.URI + ": " + err.Error()}
		}
		referenced[index] = signapp.ReferencedDocument{URI: document.URI, Digest: digest, MimeType: document.MimeType}
	}
	signature, err := s.xades.SignXades(ctx, signapp.XadesRequest{Signer: request.Key, Level: level, Packaging: signing.XMLDetached,
		Referenced: referenced, Manifest: domain.UsesManifest(request.Properties), TimestampURL: tsa, Policy: policy,
		ClaimedRoles: domain.ClaimedRoles(request.Properties), Place: productionPlace(request.Properties)})
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

// productionPlace is the place the page asks the signature to declare.
func productionPlace(properties map[string]string) signing.ProductionPlace {
	city, province, postalCode, country := domain.ProductionPlace(properties)
	return signing.ProductionPlace{City: city, Province: province, PostalCode: postalCode, Country: country}
}

// signOffice signs an office document inside itself, as AutoFirma's ODF
// and OOXML signers, LibreOffice and Microsoft Office do.
func (s NativePageSigner) signOffice(ctx context.Context, request application.PageSignature, family string,
	level signing.Level, tsa string, policy signing.SignaturePolicy) ([]byte, error) {
	if request.Crypto != domain.Sign {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "an office document takes more signatures by being signed again"}
	}
	xadesRequest := signapp.XadesRequest{Content: request.Data, Signer: request.Key, Level: level,
		TimestampURL: tsa, Policy: policy, ClaimedRoles: domain.ClaimedRoles(request.Properties)}
	sign := s.odf.SignOdf
	if family == "ooxml" {
		sign = s.ooxml.SignOoxml
	}
	signed, err := sign(ctx, xadesRequest)
	switch {
	case errors.Is(err, signinfra.ErrNotOpenDocument), errors.Is(err, signinfra.ErrNotOfficeOpenXML):
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
	if request.Crypto == domain.Cosign || request.Crypto == domain.Countersign {
		return s.addToASiC(ctx, request, level, tsa, policy)
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
			ClaimedRoles: domain.ClaimedRoles(request.Properties)})
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

// addToASiC adds signatures to the container the page sends, as
// AutoFirma's cosign and countersign of CAdES-ASiC-S and XAdES-ASiC-S do: a
// parallel signature of the kind it holds (the CAdES signature co-signed in
// place, or one more XAdES signature in its signatures file, refused when
// it would break another), or counter-signatures of its signatures where
// they are, leaves or the whole tree as the page's target says.
func (s NativePageSigner) addToASiC(ctx context.Context, request application.PageSignature, level signing.Level, tsa string,
	policy signing.SignaturePolicy) ([]byte, error) {
	if !bytes.HasPrefix(request.Data, []byte("PK\x03\x04")) {
		return nil, domain.Failure{Code: domain.NoSignData, Cause: "a signature added to an ASiC container needs the container"}
	}
	adding := signapp.Request{Signer: request.Key, Level: level, TimestampURL: tsa, Policy: policy,
		ClaimedRoles: domain.ClaimedRoles(request.Properties)}
	var signed signapp.SignedContainer
	var err error
	if request.Crypto == domain.Countersign {
		adding.Countersign = domain.CounterTarget(request.Properties)
		signed, err = signapp.NewCountersignContainer(signinfra.AsicContainers{}, s.cades, s.xades).Execute(ctx, adding, request.Data)
	} else {
		signed, err = signapp.NewCosignContainer(signinfra.AsicContainers{}, s.cades, s.xades).Execute(ctx, adding, request.Data)
	}
	if err != nil {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	return signed.Content, nil
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

// Neighbours returns the other certificates of the key's store: a card's
// other identities; a file holds one.
func (KeyCertificates) Neighbours(key signing.Signer) ([][]byte, error) {
	pair, err := signinfra.LoadKeyPair(key)
	if err != nil {
		return nil, err
	}
	defer pair.Close()
	raws := make([][]byte, 0, len(pair.Neighbours))
	for _, neighbour := range pair.Neighbours {
		raws = append(raws, neighbour.Raw)
	}
	return raws, nil
}

// compile-time checks.
var (
	_ application.PageSigner        = NativePageSigner{}
	_ application.CertificateReader = KeyCertificates{}
)
