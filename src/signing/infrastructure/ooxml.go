package infrastructure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/opc"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// ErrNotOfficeOpenXML means bytes that are not an Office Open XML package.
var ErrNotOfficeOpenXML = opc.ErrNotPackage

// OoxmlSigner signs Office Open XML files (.docx, .xlsx, .pptx) inside
// themselves, as Microsoft Office and LibreOffice do (ECMA-376 Part 2, §13;
// [MS-OFFCRYPTO] 2.5.2): one signature part under _xmlsignatures, whose
// Manifest digests every part of the package but the document properties
// applications rewrite, the relationships through the RelationshipTransform.
// The parts earlier signatures cover are not touched, so they stay valid.
type OoxmlSigner struct {
	xades *XadesSigner
}

// NewOoxmlSigner builds the adapter over the XML signer, whose timestamps
// and unsigned properties it shares.
func NewOoxmlSigner(xades *XadesSigner) *OoxmlSigner {
	return &OoxmlSigner{xades: xades}
}

// Office's Ids. Each signature lives in a part of its own, so fixed Ids do
// not collide, and they are the ones Office writes.
const (
	ooxmlSignatureID        = "idPackageSignature"
	ooxmlPackageObjectID    = "idPackageObject"
	ooxmlOfficeObjectID     = "idOfficeObject"
	ooxmlSignedPropertiesID = "idSignedProperties"

	typeObject               = "http://www.w3.org/2000/09/xmldsig#Object"
	namespaceOfficeSignature = "http://schemas.microsoft.com/office/2006/digsig"
)

// SignOoxml signs the package in request.Content.
func (s *OoxmlSigner) SignOoxml(ctx context.Context, request application.XadesRequest) ([]byte, error) {
	if err := levelReady(request); err != nil {
		return nil, err
	}
	pkg, err := opc.Open(request.Content)
	if err != nil {
		return nil, err
	}
	if err := pkg.CompactRelationships(); err != nil {
		return nil, err
	}
	references, err := pkg.SignedReferences()
	if err != nil {
		return nil, err
	}
	if len(references) == 0 {
		return nil, fmt.Errorf("the package has nothing to sign")
	}

	keyPair, err := LoadKeyPair(request.Signer)
	if err != nil {
		return nil, err
	}
	defer keyPair.Close()

	signature, err := s.signature(ctx, request, keyPair, references)
	if err != nil {
		return nil, err
	}
	return pkg.WithSignature(signature)
}

// signature builds the signature part: the skeleton with Office's objects,
// then each SignedInfo reference digested where it stands, the SignedInfo
// signed, and the unsigned properties the level asks for.
func (s *OoxmlSigner) signature(ctx context.Context, request application.XadesRequest, keyPair KeyPair,
	references []opc.Reference) ([]byte, error) {
	signedAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	tree, err := parseDocument([]byte(ooxmlSkeleton(request, keyPair.Certificate, references, signedAt)))
	if err != nil {
		return nil, err
	}
	signatureElement := tree.Root()
	signedInfo := signatureElement.SelectElement("SignedInfo")
	for _, reference := range signedInfo.SelectElements("Reference") {
		data, err := xmldsig.ReferenceData(tree, signatureElement, reference, nil)
		if err != nil {
			return nil, fmt.Errorf("digest %s: %w", reference.SelectAttrValue("URI", ""), err)
		}
		digest := sha256.Sum256(data)
		setDigestValue(reference, digest[:])
	}

	signedInfoDigest, err := canonicalDigest(signedInfo)
	if err != nil {
		return nil, err
	}
	value, err := keyPair.Signer.Sign(rand.Reader, signedInfoDigest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign the package signature: %w", err)
	}
	if key, ok := keyPair.Certificate.PublicKey.(*ecdsa.PublicKey); ok {
		if value, err = xmldsigECDSA(key, value); err != nil {
			return nil, err
		}
	}
	signatureElement.SelectElement("SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))

	if err := s.xades.extend(ctx, tree, signatureElement, request, keyPair, nil); err != nil {
		return nil, err
	}
	return tree.WriteToBytes()
}

// ooxmlSkeleton writes the signature as Office 2010 and later do, with
// placeholder digests: SignedInfo over the package object, the Office
// object and the signed properties; the package object holding the
// Manifest of parts and the signing time.
func ooxmlSkeleton(request application.XadesRequest, certificate *x509.Certificate, references []opc.Reference, signedAt string) string {
	method := algorithmRSASHA256
	if certificate.PublicKeyAlgorithm == x509.ECDSA {
		method = algorithmECDSASHA256
	}
	digest := `<DigestMethod Algorithm="` + algorithmSHA256 + `"/><DigestValue>` + placeholderDigest + `</DigestValue>`
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<Signature xmlns="` + namespaceDS + `" Id="` + ooxmlSignatureID + `">` +
		`<SignedInfo>` +
		`<CanonicalizationMethod Algorithm="` + algorithmC14N + `"/>` +
		`<SignatureMethod Algorithm="` + method + `"/>` +
		`<Reference Type="` + typeObject + `" URI="#` + ooxmlPackageObjectID + `">` + digest + `</Reference>` +
		`<Reference Type="` + typeObject + `" URI="#` + ooxmlOfficeObjectID + `">` + digest + `</Reference>` +
		`<Reference Type="` + typeSignedProperties + `" URI="#` + ooxmlSignedPropertiesID + `">` +
		`<Transforms><Transform Algorithm="` + algorithmC14N + `"/></Transforms>` + digest + `</Reference>` +
		`</SignedInfo>` +
		`<SignatureValue>` + placeholderDigest + `</SignatureValue>` +
		`<KeyInfo><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(certificate.Raw) +
		`</X509Certificate></X509Data></KeyInfo>` +
		packageObject(references, signedAt) +
		officeObject() +
		`<Object><xd:QualifyingProperties xmlns:xd="` + namespaceXades +
		`" Target="#` + ooxmlSignatureID + `">` + ooxmlSignedProperties(request, certificate, signedAt) +
		`</xd:QualifyingProperties></Object>` +
		`</Signature>`
}

// packageObject is the package-specific object (§13.2.4.13): the Manifest
// of parts, each digested as opc computed it, and the signing time.
func packageObject(references []opc.Reference, signedAt string) string {
	var manifest strings.Builder
	for _, reference := range references {
		manifest.WriteString(`<Reference URI="` + xmlEscape(reference.URI) + `">`)
		if reference.Relationships != nil {
			manifest.WriteString(`<Transforms><Transform Algorithm="` + opc.RelationshipTransform + `">`)
			for _, id := range reference.Relationships {
				manifest.WriteString(`<mdssi:RelationshipReference SourceId="` + xmlEscape(id) + `"/>`)
			}
			manifest.WriteString(`</Transform><Transform Algorithm="` + algorithmC14N + `"/></Transforms>`)
		}
		digest := sha256.Sum256(reference.Data)
		manifest.WriteString(`<DigestMethod Algorithm="` + algorithmSHA256 + `"/><DigestValue>` +
			base64.StdEncoding.EncodeToString(digest[:]) + `</DigestValue></Reference>`)
	}
	return `<Object Id="` + ooxmlPackageObjectID + `" xmlns:mdssi="` + opc.NamespaceSignature + `">` +
		`<Manifest>` + manifest.String() + `</Manifest>` +
		`<SignatureProperties><SignatureProperty Id="idSignatureTime" Target="#` + ooxmlSignatureID + `">` +
		`<mdssi:SignatureTime><mdssi:Format>YYYY-MM-DDThh:mm:ssTZD</mdssi:Format>` +
		`<mdssi:Value>` + signedAt + `</mdssi:Value></mdssi:SignatureTime>` +
		`</SignatureProperty></SignatureProperties></Object>`
}

// officeObject is Office's SignatureInfoV1 ([MS-OFFCRYPTO] 2.5.2.5), in
// the order Office 2010 writes it. The schema requires the display
// description; it matters only for a visible signature line, which this
// signature does not draw (SignatureType 1), and the values are the ones
// LibreOffice writes.
func officeObject() string {
	return `<Object Id="` + ooxmlOfficeObjectID + `"><SignatureProperties>` +
		`<SignatureProperty Id="idOfficeV1Details" Target="#` + ooxmlSignatureID + `">` +
		`<SignatureInfoV1 xmlns="` + namespaceOfficeSignature + `">` +
		`<SetupID/><SignatureText/><SignatureImage/><SignatureComments/>` +
		`<WindowsVersion>6.1</WindowsVersion><OfficeVersion>16.0</OfficeVersion><ApplicationVersion>16.0</ApplicationVersion>` +
		`<Monitors>1</Monitors><HorizontalResolution>1280</HorizontalResolution><VerticalResolution>800</VerticalResolution>` +
		`<ColorDepth>24</ColorDepth>` +
		`<SignatureProviderId>{00000000-0000-0000-0000-000000000000}</SignatureProviderId><SignatureProviderUrl/>` +
		`<SignatureProviderDetails>9</SignatureProviderDetails>` +
		`<ManifestHashAlgorithm>` + algorithmSHA256 + `</ManifestHashAlgorithm>` +
		`<SignatureType>1</SignatureType>` +
		`</SignatureInfoV1></SignatureProperty></SignatureProperties></Object>`
}

// ooxmlSignedProperties are XAdES signed properties as Office writes them,
// prefix included: SigningCertificate with the issuer and serial, and an
// implied policy unless the request declares one.
func ooxmlSignedProperties(request application.XadesRequest, certificate *x509.Certificate, signedAt string) string {
	certificateDigest := sha256.Sum256(certificate.Raw)
	policy := `<xd:SignaturePolicyIdentifier><xd:SignaturePolicyImplied/></xd:SignaturePolicyIdentifier>`
	if !request.Policy.IsZero() {
		policy = withXadesPrefixes(policyProperties(request.Policy))
	}
	return `<xd:SignedProperties Id="` + ooxmlSignedPropertiesID + `"><xd:SignedSignatureProperties>` +
		`<xd:SigningTime>` + signedAt + `</xd:SigningTime>` +
		`<xd:SigningCertificate><xd:Cert><xd:CertDigest>` +
		`<DigestMethod Algorithm="` + algorithmSHA256 + `"/>` +
		`<DigestValue>` + base64.StdEncoding.EncodeToString(certificateDigest[:]) + `</DigestValue>` +
		`</xd:CertDigest><xd:IssuerSerial>` +
		`<X509IssuerName>` + xmlEscape(certificate.Issuer.String()) + `</X509IssuerName>` +
		`<X509SerialNumber>` + certificate.SerialNumber.String() + `</X509SerialNumber>` +
		`</xd:IssuerSerial></xd:Cert></xd:SigningCertificate>` +
		policy + withXadesPrefixes(roleProperties(request.ClaimedRoles)) +
		`</xd:SignedSignatureProperties></xd:SignedProperties>`
}

// withXadesPrefixes declares, on the root of a fragment the XAdES signer
// writes, the xades: and ds: prefixes it uses.
func withXadesPrefixes(fragment string) string {
	end := strings.IndexAny(fragment, " >")
	if end < 0 {
		return fragment
	}
	return fragment[:end] + ` xmlns:xades="` + namespaceXades + `" xmlns:ds="` + namespaceDS + `"` + fragment[end:]
}

var _ application.OoxmlSigner = (*OoxmlSigner)(nil)
