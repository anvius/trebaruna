package cms

// What a long-term signature carries beside it: the certificates a
// SignedData holds, the signature timestamps its signers took, and the
// validation data the CAdES baseline profile keeps in SignedData.

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"slices"
)

// signatureTimeStampType is id-aa-signatureTimeStampToken as encoded.
var signatureTimeStampType, _ = asn1.Marshal(OIDTimeStampToken)

// Certificates returns the certificates a SignedData carries, each as it
// is encoded; other kinds of CertificateChoices are left out. Bytes after
// the ContentInfo, the padding of a PDF's /Contents, are ignored, as the
// reader reads one element.
func Certificates(contentInfoDER []byte) ([][]byte, error) {
	parts, err := splitSignedData(contentInfoDER)
	if err != nil || parts.certificates == nil {
		return nil, err
	}
	_, _, body, err := parseTLV(parts.certificates)
	if err != nil {
		return nil, err
	}
	elements, err := splitElements(body)
	if err != nil {
		return nil, err
	}
	var certificates [][]byte
	for _, element := range elements {
		if element[0] == 0x30 {
			certificates = append(certificates, element)
		}
	}
	return certificates, nil
}

// SignatureTimeStampTokens returns the signature timestamp tokens of every
// SignerInfo of a SignedData, in order.
func SignatureTimeStampTokens(contentInfoDER []byte) ([][]byte, error) {
	parts, err := splitSignedData(contentInfoDER)
	if err != nil {
		return nil, err
	}
	signers, err := splitSequence(parts.signerInfos)
	if err != nil {
		return nil, err
	}
	var tokens [][]byte
	for _, signer := range signers {
		fields, err := splitSequence(signer)
		if err != nil || len(fields) < 6 {
			continue
		}
		for _, field := range fields[6:] {
			if field[0] != 0xa1 {
				continue
			}
			_, _, body, err := parseTLV(field)
			if err != nil {
				return nil, err
			}
			attributes, err := splitElements(body)
			if err != nil {
				return nil, err
			}
			for _, attribute := range attributes {
				if attributeType, values, err := splitAttribute(attribute); err == nil && bytes.Equal(attributeType, signatureTimeStampType) {
					tokens = append(tokens, values...)
				}
			}
		}
	}
	return tokens, nil
}

// oidOCSPResponseRevocation is id-ri-ocsp-response (RFC 5940, 4.1): an
// OCSPResponse carried among a SignedData's revocation information.
var oidOCSPResponseRevocation = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 16, 2}

// WithValidationData puts what a long-term signature needs where the CAdES
// baseline profile asks for it (EN 319 122-1, B-LT): the certificates in
// SignedData.certificates, and the revocation information in
// SignedData.crls, each CRL as it is and each OCSP answer as an
// OtherRevocationInfoFormat holding the OCSPResponse the responder sent
// (RFC 5940). Neither field is signed, so the signatures are untouched;
// what is already there is kept, and nothing is added twice. With an
// "other" revocation choice SignedData is version 5 (RFC 5652, 5.1).
func WithValidationData(contentInfoDER []byte, certificates, crls, ocspResponses [][]byte) ([]byte, error) {
	encoder := &der{}
	contentInfoFields, err := splitSequence(contentInfoDER)
	if err != nil || len(contentInfoFields) < 2 {
		return nil, fmt.Errorf("cms: unreadable ContentInfo")
	}
	_, _, signedDataDER, err := parseTLV(contentInfoFields[1])
	if err != nil {
		return nil, err
	}
	fields, err := splitSequence(signedDataDER)
	if err != nil || len(fields) < 4 {
		return nil, fmt.Errorf("cms: unreadable SignedData")
	}

	var heldCertificates, heldRevocations [][]byte
	for _, field := range fields[3 : len(fields)-1] {
		_, _, body, err := parseTLV(field)
		if err != nil {
			return nil, err
		}
		elements, err := splitElements(body)
		if err != nil {
			return nil, err
		}
		switch field[0] {
		case 0xa0:
			heldCertificates = elements
		case 0xa1:
			heldRevocations = elements
		}
	}
	added := func(held, more [][]byte) [][]byte {
		for _, element := range more {
			if !slices.ContainsFunc(held, func(have []byte) bool { return bytes.Equal(have, element) }) {
				held = append(held, element)
			}
		}
		return held
	}
	heldCertificates = added(heldCertificates, certificates)
	revocations := append([][]byte{}, crls...)
	for _, response := range ocspResponses {
		revocations = append(revocations, encoder.tagged(0xa1, encoder.oid(oidOCSPResponseRevocation), response))
	}
	heldRevocations = added(heldRevocations, revocations)

	version := fields[0]
	if len(ocspResponses) > 0 {
		version = encoder.integer(5)
	}
	rebuilt := [][]byte{version, fields[1], fields[2]}
	if len(heldCertificates) > 0 {
		rebuilt = append(rebuilt, encoder.tagged(0xa0, heldCertificates...))
	}
	if len(heldRevocations) > 0 {
		rebuilt = append(rebuilt, encoder.tagged(0xa1, heldRevocations...))
	}
	rebuilt = append(rebuilt, fields[len(fields)-1])
	return encoder.seq(encoder.oid(OIDSignedData), encoder.tagged(0xa0, encoder.tagged(0x30, rebuilt...))), nil
}
