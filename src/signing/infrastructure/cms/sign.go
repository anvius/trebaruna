package cms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

// Request describes a CAdES signature to produce.
type Request struct {
	Content            []byte
	Certificate        *x509.Certificate
	Chain              []*x509.Certificate
	Signer             crypto.Signer
	EmbeddedContent    bool
	IncludeSigningTime bool
	ExtraAttributes    []Attribute
	// Countersignature omits the contentType attribute: a counter-signature
	// signs another signature, not content (RFC 5652 §11.4).
	Countersignature bool
	// ContentType is the eContentType of the encapsulated content. Empty means
	// id-data, which is what a CAdES document signature carries. A timestamp
	// token declares id-ct-TSTInfo instead, and validators check it.
	ContentType asn1.ObjectIdentifier
}

// Signature is the produced SignedData plus the material needed to timestamp
// it afterwards. Timestamping CAdES requires the value that was actually
// signed, which the caller does not otherwise have.
type Signature struct {
	DER            []byte
	SignatureValue []byte
	signedAttrs    []byte
	digestValue    []byte
}

// Sign produces a CMS SignedData with the CAdES-required signed attributes.
func Sign(request Request) (Signature, error) {
	if len(request.Content) == 0 {
		return Signature{}, ErrEmptyContent
	}
	if request.Certificate == nil || request.Signer == nil {
		return Signature{}, fmt.Errorf("cms: certificate and signer are required")
	}

	contentDigest := sha256.Sum256(request.Content)
	signedAttrsDER, err := buildSignedAttributes(contentDigest[:], request)
	if err != nil {
		return Signature{}, err
	}

	// The signature covers the DER of the attributes, re-tagged as a SET OF,
	// not the SEQUENCE form that goes into the container. This re-tag is the
	// single most common source of broken CMS implementations.
	signedAttrsForSignature := retagAsSet(signedAttrsDER)

	attrsDigest := sha256.Sum256(signedAttrsForSignature)
	signatureValue, err := request.Signer.Sign(rand.Reader, attrsDigest[:], crypto.SHA256)
	if err != nil {
		return Signature{}, fmt.Errorf("cms: sign attributes: %w", err)
	}

	der, err := assemble(request, signedAttrsDER, signatureValue)
	if err != nil {
		return Signature{}, err
	}

	return Signature{
		DER:            der,
		SignatureValue: signatureValue,
		signedAttrs:    signedAttrsForSignature,
		digestValue:    contentDigest[:],
	}, nil
}

// WithTimestamp rebuilds the container with an RFC 3161 token attached as an
// unsigned attribute, which is what makes it CAdES-T.
//
// The input must be the TimeStampResp returned by the TSA; the attribute needs
// only the TimeStampToken inside it. Embedding the whole response produces a
// container that OpenSSL parses but that strict validators reject, because
// signature-time-stamp-token is defined as a ContentInfo, not a TimeStampResp.
func (s Signature) WithTimestamp(responseDER []byte) ([]byte, error) {
	if s.DER == nil {
		return nil, fmt.Errorf("cms: signature not built")
	}
	tokenDER, err := ExtractToken(responseDER)
	if err != nil {
		return nil, err
	}
	return appendUnsignedAttribute(s.DER, OIDTimeStampToken, tokenDER)
}

// ExtractToken returns the TimeStampToken contained in a TimeStampResp.
func ExtractToken(responseDER []byte) ([]byte, error) {
	fields, err := splitSequence(responseDER)
	if err != nil {
		return nil, fmt.Errorf("cms: cannot split timestamp response: %w", err)
	}
	if len(fields) < 2 {
		return nil, fmt.Errorf(
			"cms: timestamp response has %d fields, expected 2 (status + token); "+
				"the TSA probably refused the request",
			len(fields),
		)
	}
	return fields[len(fields)-1], nil
}

// buildSignedAttributes creates the SEQUENCE of attributes that will be signed.
func buildSignedAttributes(contentDigest []byte, request Request) ([]byte, error) {
	encoder := &der{}

	var attributes [][]byte
	if !request.Countersignature {
		attributes = append(attributes, encoder.seq(
			encoder.oid(OIDContentType),
			encoder.set(encoder.oid(contentTypeFor(request))),
		))
	}
	attributes = append(attributes, encoder.seq(
		encoder.oid(OIDMessageDigest),
		encoder.set(encoder.octetString(contentDigest)),
	))

	if request.IncludeSigningTime {
		attributes = append(attributes, encoder.seq(
			encoder.oid(OIDSigningTime),
			encoder.set(encoder.utcTime(formatUTCTime(time.Now()))),
		))
	}

	essAttribute, err := signingCertificateV2(encoder, request.Certificate)
	if err != nil {
		return nil, err
	}
	attributes = append(attributes, essAttribute)

	for _, extra := range request.ExtraAttributes {
		attributes = append(attributes, encoder.seq(
			encoder.oid(extra.Type),
			encoder.set(extra.Value),
		))
	}

	return encoder.tagged(0x30, sortSet(attributes)...), nil
}

// contentTypeFor returns the declared content type, defaulting to id-data.
func contentTypeFor(request Request) asn1.ObjectIdentifier {
	if len(request.ContentType) == 0 {
		return OIDData
	}
	return request.ContentType
}

// signingCertificateV2 encodes ESSCertIDv2 per RFC 5035.
func signingCertificateV2(encoder *der, certificate *x509.Certificate) ([]byte, error) {
	digest := sha256.Sum256(certificate.Raw)

	// ESSCertIDv2 ::= SEQUENCE { hashAlgorithm [0] DEFAULT sha256, certHash OCTET STRING, ... }
	// The DEFAULT is omitted when SHA-256 is used, which is our case.
	essCertID := encoder.seq(encoder.octetString(digest[:]))
	scv2 := encoder.seq(encoder.seq(essCertID))

	return encoder.seq(
		encoder.oid(OIDSigningCertificateV2),
		encoder.set(scv2),
	), nil
}

// assemble builds the final ContentInfo.
func assemble(request Request, signedAttrs, signatureValue []byte) ([]byte, error) {
	encoder := &der{}

	algorithm := digestAlgorithmFor(request.Signer, request.Certificate)
	signatureAlgorithm, err := signatureAlgorithmFor(request.Certificate)
	if err != nil {
		return nil, err
	}

	contentType := request.ContentType
	if len(contentType) == 0 {
		contentType = OIDData
	}

	var encapContent []byte
	if request.EmbeddedContent {
		encapContent = encoder.seq(
			encoder.oid(contentType),
			encoder.tagged(0xa0, encoder.octetString(request.Content)),
		)
	} else {
		encapContent = encoder.seq(encoder.oid(contentType))
	}

	certificates := encoder.tagged(0xa0, certificateSet(encoder, request)...)

	// signedAttrs is [0] IMPLICIT SET OF Attribute in the wire format, but the
	// signature itself is computed over the SET OF encoding (0x31) produced by
	// retagAsSet. Emitting the SEQUENCE form here makes OpenSSL fail with
	// "nested asn1 error in Field=signerInfos".
	signedAttrsImplicit := make([]byte, len(signedAttrs))
	copy(signedAttrsImplicit, signedAttrs)
	signedAttrsImplicit[0] = 0xa0

	signerInfo := encoder.seq(
		encoder.integer(1),
		issuerAndSerial(encoder, request.Certificate),
		algorithm,
		signedAttrsImplicit,
		signatureAlgorithm,
		encoder.octetString(signatureValue),
	)

	signedData := encoder.seq(
		encoder.integer(1),
		encoder.set(algorithm),
		encapContent,
		certificates,
		encoder.set(signerInfo),
	)

	return encoder.seq(encoder.oid(OIDSignedData), encoder.tagged(0xa0, signedData)), nil
}

// certificateSet encodes the signer chain, leaf first.
//
// CertificateSet is a SET OF CertificateChoices, but CertificateChoices is a
// CHOICE with an implicit tag: sorting the outer encodings breaks parsing,
// because the elements are not raw DER SEQUENCEs but IMPLICIT [0] tagged ones.
// OpenSSL rejects a sorted set here, so insertion order is preserved.
func certificateSet(_ *der, request Request) [][]byte {
	// x509.Certificate.Raw is already a complete DER SEQUENCE: wrapping it in
	// another SEQUENCE produces a double-tagged certificate that OpenSSL
	// rejects with "nested asn1 error in Field=certificates".
	encoded := [][]byte{request.Certificate.Raw}
	for _, issuer := range request.Chain {
		encoded = append(encoded, issuer.Raw)
	}
	return encoded
}

// issuerAndSerial identifies the signer, which is cheaper to verify than a
// subject key identifier and universally supported.
func issuerAndSerial(encoder *der, certificate *x509.Certificate) []byte {
	return encoder.seq(certificate.RawIssuer, ensurePositiveInteger(certificate.SerialNumber.Bytes()))
}

// ensurePositiveInteger prepends 0x00 when the high bit is set, so ASN.1 reads
// the serial as positive rather than two's-complement negative.
func ensurePositiveInteger(value []byte) []byte {
	if len(value) == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	if value[0]&0x80 != 0 {
		value = append([]byte{0x00}, value...)
	}
	out := make([]byte, 0, len(value)+3)
	out = append(out, 0x02)
	out = append(out, encodeLength(len(value))...)
	out = append(out, value...)
	return out
}

// digestAlgorithmFor returns the SHA-256 AlgorithmIdentifier.
func digestAlgorithmFor(_ crypto.Signer, _ *x509.Certificate) []byte {
	encoder := &der{}
	return encoder.seq(encoder.oid(OIDSHA256), encoder.null())
}

// signatureAlgorithmFor picks the signature OID that matches the key type.
func signatureAlgorithmFor(certificate *x509.Certificate) ([]byte, error) {
	encoder := &der{}
	oid, err := signatureOIDFor(certificate.PublicKeyAlgorithm)
	if err != nil {
		return nil, err
	}
	if certificate.PublicKeyAlgorithm == x509.RSA {
		return encoder.seq(encoder.oid(oid), encoder.null()), nil
	}
	return encoder.seq(encoder.oid(oid)), nil
}

func signatureOIDFor(algorithm x509.PublicKeyAlgorithm) (asn1.ObjectIdentifier, error) {
	switch algorithm {
	case x509.RSA:
		// The PSS variant is not used here: interoperable CAdES in Italy is
		// overwhelmingly RSA-PKCS1v15.
		return OIDSHA256WithRSA, nil
	case x509.ECDSA:
		return OIDSHA256WithECDSA, nil
	}
	return nil, fmt.Errorf("cms: unsupported public key algorithm %v (only RSA and ECDSA)", algorithm)
}

// retagAsSet rewrites the outer SEQUENCE tag (0x30) to SET (0x31).
func retagAsSet(derBytes []byte) []byte {
	if len(derBytes) == 0 || derBytes[0] != 0x30 {
		return derBytes
	}
	copied := make([]byte, len(derBytes))
	copy(copied, derBytes)
	copied[0] = 0x31
	return copied
}

// formatUTCTime renders YYMMDDHHMMSSZ, as RFC 5652 requires for signingTime.
func formatUTCTime(moment time.Time) string {
	return moment.UTC().Format("060102150405Z")
}

// ensure the RSA key type is understood at compile time.
var _ = rsa.ErrVerification
