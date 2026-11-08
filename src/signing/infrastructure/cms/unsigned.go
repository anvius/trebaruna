package cms

import (
	"encoding/asn1"
	"fmt"
)

// appendUnsignedAttribute takes an existing ContentInfo DER and injects an
// attribute into the unsignedAttrs of every SignerInfo.
//
// The strategy is deliberately shallow: parse only the outer structure with
// encoding/asn1, splice the bytes of the signerInfos set, and re-emit. Deep
// parsing of an RFC 3161 token is unnecessary and error-prone, because the
// token must be embedded verbatim for validators to check its own signature.
func appendUnsignedAttribute(contentInfoDER []byte, attributeOID asn1.ObjectIdentifier, valueDER []byte) ([]byte, error) {
	encoder := &der{}
	attribute := encoder.seq(
		encoder.oid(attributeOID),
		encoder.set(valueDER),
	)

	// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }.
	// asn1.Unmarshal would stop at the OID, so the two fields are split by hand.
	contentInfoFields, err := splitSequence(contentInfoDER)
	if err != nil {
		return nil, fmt.Errorf("cms: cannot split ContentInfo: %w", err)
	}
	if len(contentInfoFields) < 2 {
		return nil, fmt.Errorf("cms: ContentInfo has %d fields, expected 2", len(contentInfoFields))
	}

	// The [0] wrapper holds the SignedData SEQUENCE verbatim.
	_, _, signedDataDER, err := parseTLV(contentInfoFields[len(contentInfoFields)-1])
	if err != nil {
		return nil, fmt.Errorf("cms: cannot parse SignedData wrapper: %w", err)
	}

	signedDataFields, err := splitSequence(signedDataDER)
	if err != nil {
		return nil, fmt.Errorf("cms: cannot split SignedData: %w", err)
	}
	if len(signedDataFields) < 5 {
		return nil, fmt.Errorf("cms: SignedData has %d fields, expected at least 5", len(signedDataFields))
	}

	signerInfosDER := signedDataFields[len(signedDataFields)-1]
	rebuiltSignerInfos, err := injectIntoSignerInfos(signerInfosDER, attribute)
	if err != nil {
		return nil, err
	}

	rebuilt := make([][]byte, 0, len(signedDataFields))
	rebuilt = append(rebuilt, signedDataFields[:len(signedDataFields)-1]...)
	rebuilt = append(rebuilt, rebuiltSignerInfos)

	newSignedData := encoder.tagged(0x30, rebuilt...)
	return encoder.seq(encoder.oid(OIDSignedData), encoder.tagged(0xa0, newSignedData)), nil
}

// injectIntoSignerInfos rebuilds the SET OF SignerInfo with the attribute
// added to each entry.
func injectIntoSignerInfos(signerInfosDER []byte, attribute []byte) ([]byte, error) {
	encoder := &der{}

	body, err := sequenceBody(signerInfosDER)
	if err != nil {
		return nil, err
	}

	entries, err := splitElements(body)
	if err != nil {
		return nil, err
	}

	rebuilt := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		updated, err := addUnsignedAttribute(entry, attribute)
		if err != nil {
			return nil, err
		}
		rebuilt = append(rebuilt, updated)
	}

	return encoder.tagged(0x31, rebuilt...), nil
}

// addUnsignedAttribute appends to an existing unsignedAttrs or creates it.
func addUnsignedAttribute(signerInfoDER []byte, attribute []byte) ([]byte, error) {
	encoder := &der{}

	fields, err := splitSequence(signerInfoDER)
	if err != nil {
		return nil, err
	}

	// SignerInfo v1: version, sid, digestAlgorithm, signedAttrs,
	// signatureAlgorithm, signature, unsignedAttrs?
	if len(fields) < 6 {
		return nil, fmt.Errorf("cms: SignerInfo has %d fields, expected at least 6", len(fields))
	}

	rebuilt := make([][]byte, 0, len(fields)+1)
	rebuilt = append(rebuilt, fields[:6]...)

	if len(fields) == 6 {
		// No unsignedAttrs yet: create the [1] IMPLICIT wrapper.
		rebuilt = append(rebuilt, encoder.tagged(0xa1, attribute))
		return encoder.tagged(0x30, rebuilt...), nil
	}

	// Append to the existing wrapper's contents.
	existing := fields[6]
	_, _, contents, err := parseTLV(existing)
	if err != nil {
		return nil, fmt.Errorf("cms: cannot parse unsignedAttrs: %w", err)
	}
	rebuilt = append(rebuilt, encoder.tagged(0xa1, append(contents, attribute...)))
	rebuilt = append(rebuilt, fields[7:]...)

	return encoder.tagged(0x30, rebuilt...), nil
}

// RevocationValues builds the CAdES-LT attribute payload.
//
//	RevocationValues ::= SEQUENCE {
//	    crlVals  [0] SEQUENCE OF OCTET STRING OPTIONAL,
//	    ocspVals [1] SEQUENCE OF OCTET STRING OPTIONAL }
//
// The entries are the DER of the CRLs and BasicOCSPResponses as the responders
// produced them: a validator re-parses them, so re-encoding would break the
// signature the responder attached.
func RevocationValues(ocspResponses, crls [][]byte) []byte {
	encoder := &der{}

	var fields [][]byte
	if len(crls) > 0 {
		entries := make([][]byte, 0, len(crls))
		for _, crl := range crls {
			entries = append(entries, encoder.octetString(crl))
		}
		fields = append(fields, encoder.tagged(0xa0, entries...))
	}
	if len(ocspResponses) > 0 {
		entries := make([][]byte, 0, len(ocspResponses))
		for _, response := range ocspResponses {
			entries = append(entries, encoder.octetString(response))
		}
		fields = append(fields, encoder.tagged(0xa1, entries...))
	}
	return encoder.seq(fields...)
}

// WithRevocationValues rebuilds the container with a RevocationValues attribute.
//
// This is what turns CAdES-T into CAdES-LT: the signature bytes are untouched and
// the validation material is attached beside them, so the signature keeps
// verifying after the responders disappear.
func (s Signature) WithRevocationValues(ocspResponses, crls [][]byte) ([]byte, error) {
	if s.DER == nil {
		return nil, fmt.Errorf("cms: signature not built")
	}
	return appendUnsignedAttribute(s.DER, OIDRevocationValues,
		RevocationValues(ocspResponses, crls))
}

// WithRevocationValuesFrom attaches RevocationValues to an existing container.
//
// The method form needs a Signature value, which the CAdES adapter does not keep
// once the timestamp has been appended and the bytes rebuilt. This entry point
// takes the container itself, so the caller can attach the material after any
// number of unsigned attributes have already been added.
func WithRevocationValuesFrom(signedDER []byte, ocspResponses, crls [][]byte) ([]byte, error) {
	if len(signedDER) == 0 {
		return nil, fmt.Errorf("cms: no container to extend")
	}
	return appendUnsignedAttribute(signedDER, OIDRevocationValues,
		RevocationValues(ocspResponses, crls))
}

// WithArchiveTimeStamp attaches the CAdES-LTA archive timestamp.
//
// The token is produced by the caller over the digest of the container as it
// stands, so everything already attached is covered. Adding anything afterwards
// invalidates it, which is why this is the last step.
func WithArchiveTimeStamp(signedDER, tokenDER []byte) ([]byte, error) {
	if len(signedDER) == 0 {
		return nil, fmt.Errorf("cms: no container to archive")
	}
	if len(tokenDER) == 0 {
		return nil, fmt.Errorf("cms: no archive timestamp token")
	}
	return appendUnsignedAttribute(signedDER, OIDArchiveTimeStampV3, tokenDER)
}
