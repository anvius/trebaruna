package cms

// Parallel signatures (co-signing) and counter-signatures on an existing
// SignedData, as AutoFirma and Italian signing tools do on .p7m files.
//
// A co-signature is one more SignerInfo over the same content. A
// counter-signature is a SignerInfo over another SignerInfo's signature value,
// carried as that SignerInfo's countersignature unsigned attribute (RFC 5652
// §11.4); it signs no content, so its signed attributes carry no contentType.

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/ber"
)

// OIDCountersignature identifies the countersignature attribute.
var OIDCountersignature = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}

// ErrNoContent means a detached envelope was co-signed without its document.
var ErrNoContent = errors.New("cms: the envelope is detached; the signed document is needed to co-sign it")

// Stamper obtains an RFC 3161 TimeStampResp over a signature value, for
// T-level signatures added to an existing envelope. Nil means level B.
type Stamper func(signatureValue []byte) ([]byte, error)

// CountersignScope chooses which signatures receive a counter-signature.
type CountersignScope string

const (
	// CountersignLeaves counter-signs every signature nobody has
	// counter-signed yet: the usual "I approve what is there".
	CountersignLeaves CountersignScope = "leaves"

	// CountersignAll counter-signs every signature in the tree.
	CountersignAll CountersignScope = "all"
)

// signedData is a SignedData kept as raw DER elements, so the parts we do
// not touch are written back byte for byte.
type signedData struct {
	version          []byte
	digestAlgorithms [][]byte
	encapContent     []byte
	certificates     [][]byte
	crls             []byte
	signerInfos      [][]byte
}

func parseSignedData(envelope []byte) (signedData, error) {
	normalised, err := ber.ToDER(envelope)
	if err != nil {
		return signedData{}, fmt.Errorf("cms: unreadable envelope: %w", err)
	}
	outer, err := splitSequence(normalised)
	if err != nil || len(outer) != 2 {
		return signedData{}, fmt.Errorf("cms: not a ContentInfo")
	}
	var contentType asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(outer[0], &contentType); err != nil || !contentType.Equal(OIDSignedData) {
		return signedData{}, fmt.Errorf("cms: not a SignedData envelope")
	}
	_, _, explicit, err := parseTLV(outer[1])
	if err != nil {
		return signedData{}, err
	}
	fields, err := splitSequence(explicit)
	if err != nil || len(fields) < 4 {
		return signedData{}, fmt.Errorf("cms: malformed SignedData")
	}

	parsed := signedData{version: fields[0], encapContent: fields[2]}
	if parsed.digestAlgorithms, err = setElements(fields[1]); err != nil {
		return signedData{}, err
	}
	for _, field := range fields[3 : len(fields)-1] {
		switch field[0] {
		case 0xa0:
			_, _, body, err := parseTLV(field)
			if err != nil {
				return signedData{}, err
			}
			if parsed.certificates, err = splitElements(body); err != nil {
				return signedData{}, err
			}
		case 0xa1:
			parsed.crls = field
		}
	}
	if parsed.signerInfos, err = setElements(fields[len(fields)-1]); err != nil {
		return signedData{}, err
	}
	return parsed, nil
}

func setElements(set []byte) ([][]byte, error) {
	_, _, body, err := parseTLV(set)
	if err != nil {
		return nil, err
	}
	return splitElements(body)
}

// content returns the encapsulated content and its type.
func (s signedData) content() (asn1.ObjectIdentifier, []byte, error) {
	fields, err := splitSequence(s.encapContent)
	if err != nil || len(fields) == 0 {
		return nil, nil, fmt.Errorf("cms: malformed EncapsulatedContentInfo")
	}
	var contentType asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(fields[0], &contentType); err != nil {
		return nil, nil, err
	}
	if len(fields) < 2 {
		return contentType, nil, nil
	}
	_, _, explicit, err := parseTLV(fields[1])
	if err != nil {
		return nil, nil, err
	}
	var octets []byte
	if _, err := asn1.Unmarshal(explicit, &octets); err != nil {
		return nil, nil, fmt.Errorf("cms: unreadable content: %w", err)
	}
	return contentType, octets, nil
}

func (s *signedData) addDigestAlgorithm(algorithm []byte) {
	var wanted struct{ Algorithm asn1.ObjectIdentifier }
	_, _ = asn1.Unmarshal(algorithm, &wanted)
	for _, present := range s.digestAlgorithms {
		var have struct{ Algorithm asn1.ObjectIdentifier }
		if _, err := asn1.Unmarshal(present, &have); err == nil && have.Algorithm.Equal(wanted.Algorithm) {
			return
		}
	}
	s.digestAlgorithms = append(s.digestAlgorithms, algorithm)
}

func (s *signedData) addCertificates(certificates ...[]byte) {
	for _, certificate := range certificates {
		present := false
		for _, have := range s.certificates {
			present = present || bytes.Equal(have, certificate)
		}
		if !present {
			s.certificates = append(s.certificates, certificate)
		}
	}
}

func (s signedData) encode() []byte {
	encoder := &der{}
	fields := [][]byte{s.version, encoder.tagged(0x31, s.digestAlgorithms...), s.encapContent}
	if len(s.certificates) > 0 {
		fields = append(fields, encoder.tagged(0xa0, s.certificates...))
	}
	if len(s.crls) > 0 {
		fields = append(fields, s.crls)
	}
	fields = append(fields, encoder.tagged(0x31, s.signerInfos...))
	return encoder.seq(encoder.oid(OIDSignedData), encoder.tagged(0xa0, encoder.seq(fields...)))
}

// Cosign adds a parallel signature over the envelope's content. A detached
// envelope needs its document in detachedContent.
func Cosign(envelope, detachedContent []byte, request Request, stamp Stamper) ([]byte, error) {
	parsed, err := parseSignedData(envelope)
	if err != nil {
		return nil, err
	}
	contentType, content, err := parsed.content()
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		content = detachedContent
	}
	if len(content) == 0 {
		return nil, ErrNoContent
	}

	request.ContentType = contentType
	digest := sha256.Sum256(content)
	signerInfo, err := newSignerInfo(digest[:], request, stamp)
	if err != nil {
		return nil, err
	}

	parsed.addDigestAlgorithm(digestAlgorithmFor(request.Signer, request.Certificate))
	parsed.addCertificates(certificateSet(nil, request)...)
	parsed.signerInfos = append(parsed.signerInfos, signerInfo)
	return parsed.encode(), nil
}

// Countersign adds a counter-signature to the signatures scope selects and
// returns the envelope and how many counter-signatures were added.
func Countersign(envelope []byte, request Request, scope CountersignScope, stamp Stamper) ([]byte, int, error) {
	parsed, err := parseSignedData(envelope)
	if err != nil {
		return nil, 0, err
	}
	if scope != CountersignAll {
		scope = CountersignLeaves
	}

	request.Countersignature = true
	added := 0
	countersign := func(targetSignature []byte) ([]byte, error) {
		digest := sha256.Sum256(targetSignature)
		added++
		return newSignerInfo(digest[:], request, stamp)
	}

	for index, signerInfo := range parsed.signerInfos {
		updated, err := countersignNode(signerInfo, scope, countersign)
		if err != nil {
			return nil, 0, err
		}
		parsed.signerInfos[index] = updated
	}
	if added == 0 {
		return nil, 0, fmt.Errorf("cms: the envelope carries no signature to counter-sign")
	}
	parsed.addDigestAlgorithm(digestAlgorithmFor(request.Signer, request.Certificate))
	parsed.addCertificates(certificateSet(nil, request)...)
	return parsed.encode(), added, nil
}

// signerInfoParts is a SignerInfo split into its fields.
type signerInfoParts struct {
	fields     [][]byte
	signature  []byte
	unsigned   [][]byte
	unsignedAt int
}

func splitSignerInfo(signerInfo []byte) (signerInfoParts, error) {
	fields, err := splitSequence(signerInfo)
	if err != nil || len(fields) < 5 {
		return signerInfoParts{}, fmt.Errorf("cms: malformed SignerInfo")
	}
	parts := signerInfoParts{fields: fields, unsignedAt: -1}
	for index, field := range fields {
		switch {
		case field[0] == 0x04:
			_, _, parts.signature, _ = parseTLV(field)
		case field[0] == 0xa1:
			parts.unsignedAt = index
			_, _, body, err := parseTLV(field)
			if err != nil {
				return signerInfoParts{}, err
			}
			if parts.unsigned, err = splitElements(body); err != nil {
				return signerInfoParts{}, err
			}
		}
	}
	if parts.signature == nil {
		return signerInfoParts{}, fmt.Errorf("cms: SignerInfo without a signature value")
	}
	return parts, nil
}

// countersignNode counter-signs one SignerInfo and/or its descendants.
func countersignNode(signerInfo []byte, scope CountersignScope, countersign func([]byte) ([]byte, error)) ([]byte, error) {
	parts, err := splitSignerInfo(signerInfo)
	if err != nil {
		return nil, err
	}

	var others, children [][]byte
	for _, attribute := range parts.unsigned {
		attributeFields, err := splitSequence(attribute)
		if err != nil || len(attributeFields) != 2 {
			return nil, fmt.Errorf("cms: malformed unsigned attribute")
		}
		var attributeType asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(attributeFields[0], &attributeType); err != nil {
			return nil, err
		}
		if !attributeType.Equal(OIDCountersignature) {
			others = append(others, attribute)
			continue
		}
		values, err := setElements(attributeFields[1])
		if err != nil {
			return nil, err
		}
		children = append(children, values...)
	}

	for index, child := range children {
		if children[index], err = countersignNode(child, scope, countersign); err != nil {
			return nil, err
		}
	}
	if scope == CountersignAll || len(children) == 0 {
		added, err := countersign(parts.signature)
		if err != nil {
			return nil, err
		}
		children = append(children, added)
	}

	encoder := &der{}
	unsigned := append(others, encoder.seq(encoder.oid(OIDCountersignature), encoder.tagged(0x31, children...)))
	unsignedField := encoder.tagged(0xa1, unsigned...)

	fields := append([][]byte{}, parts.fields...)
	if parts.unsignedAt >= 0 {
		fields[parts.unsignedAt] = unsignedField
	} else {
		fields = append(fields, unsignedField)
	}
	return encoder.seq(fields...), nil
}

// newSignerInfo signs a digest — of the content for a co-signature, of the
// target signature value for a counter-signature — and returns the
// SignerInfo, with its timestamp when stamp is given.
func newSignerInfo(digest []byte, request Request, stamp Stamper) ([]byte, error) {
	if request.Certificate == nil || request.Signer == nil {
		return nil, fmt.Errorf("cms: certificate and signer are required")
	}
	signedAttrs, err := buildSignedAttributes(digest, request)
	if err != nil {
		return nil, err
	}
	attrsDigest := sha256.Sum256(retagAsSet(signedAttrs))
	signatureValue, err := request.Signer.Sign(rand.Reader, attrsDigest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cms: sign attributes: %w", err)
	}

	encoder := &der{}
	signatureAlgorithm, err := signatureAlgorithmFor(request.Certificate)
	if err != nil {
		return nil, err
	}
	implicit := append([]byte{}, signedAttrs...)
	implicit[0] = 0xa0
	fields := [][]byte{
		encoder.integer(1),
		issuerAndSerial(encoder, request.Certificate),
		digestAlgorithmFor(request.Signer, request.Certificate),
		implicit,
		signatureAlgorithm,
		encoder.octetString(signatureValue),
	}

	var unsigned [][]byte
	if stamp != nil {
		response, err := stamp(signatureValue)
		if err != nil {
			return nil, err
		}
		token, err := ExtractToken(response)
		if err != nil {
			return nil, err
		}
		unsigned = append(unsigned, encoder.seq(encoder.oid(OIDTimeStampToken), encoder.set(token)))
	}
	for _, attribute := range request.Unsigned {
		unsigned = append(unsigned, encoder.seq(encoder.oid(attribute.Type), encoder.set(attribute.Value)))
	}
	if len(unsigned) > 0 {
		fields = append(fields, encoder.tagged(0xa1, unsigned...))
	}
	return encoder.seq(fields...), nil
}
