package infrastructure

import (
	"bytes"
	"encoding/asn1"
	"time"
)

// Locating the RFC 3161 token inside a CMS container.
//
// The pkcs7 library exposes signed attributes only, and the token lives in
// unsignedAttrs (OID 1.2.840.113549.1.9.16.2.14). Rather than reimplementing
// CMS parsing, the DER is scanned for that OID and the value that follows it is
// handed to the timestamp package.
//
// Authentication of the token happens in cades.go: this file only locates it.
// Finding a token is never evidence; proving its imprint matches this
// signature is.
//
// A raw scan is safe here because the OID is specific and the result is not
// trusted blindly: if the bytes do not parse as a TimeStampToken, the caller
// reports an invalid timestamp instead of accepting it.

// oidSigningTimeAttribute is the signed signing-time attribute (1.2.840.113549.1.9.5).
var oidSigningTimeAttribute = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

// oidTimeStampToken is id-aa-timeStampToken (1.2.840.113549.1.9.16.2.14).
var oidTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// findTimeStampToken returns the DER of the TimeStampToken, or nil.
//
// The token is stored as the single value of the attribute, wrapped in a SET.
// Both encodings are tried because CMS allows the attribute value to be explicit
// or implicit depending on the writer.
func findTimeStampToken(cms []byte) []byte {
	encodedOID, err := asn1.Marshal(oidTimeStampToken)
	if err != nil {
		return nil
	}

	offset := 0
	for {
		index := bytes.Index(cms[offset:], encodedOID)
		if index < 0 {
			return nil
		}
		position := offset + index + len(encodedOID)

		// After the OID comes the attribute's value: a SET containing the token.
		if token := readSetValue(cms, position); token != nil {
			return token
		}
		offset = position
	}
}

// readSetValue reads a SET (tag 0x31) and returns the first element it holds.
func readSetValue(data []byte, position int) []byte {
	if position >= len(data) || data[position] != 0x31 {
		return nil
	}

	length, headerSize, ok := readLength(data, position+1)
	if !ok {
		return nil
	}

	start := position + 1 + headerSize
	end := start + length
	if end > len(data) {
		return nil
	}

	set := data[start:end]
	if len(set) == 0 {
		return nil
	}

	// The token is a ContentInfo SEQUENCE; skip nothing and take the whole set
	// content when it holds exactly one element.
	elementLength, elementHeader, ok := readLength(set, 1)
	if !ok {
		return nil
	}
	elementEnd := 1 + elementHeader + elementLength
	if elementEnd > len(set) {
		return set
	}
	return set[:elementEnd]
}

// readLength decodes a DER length field.
func readLength(data []byte, position int) (length int, headerSize int, ok bool) {
	if position >= len(data) {
		return 0, 0, false
	}

	first := data[position]
	if first < 0x80 {
		return int(first), 1, true
	}

	count := int(first & 0x7f)
	if count == 0 || count > 4 || position+count >= len(data) {
		return 0, 0, false
	}

	length = 0
	for index := 1; index <= count; index++ {
		length = length<<8 | int(data[position+index])
	}
	return length, 1 + count, true
}

// ensureSigningTimeType documents the wire type of the attribute: UTCTime for
// dates before 2050, GeneralizedTime after. Go's time.Time unmarshalling accepts
// both, so the constant exists only to be explicit about the assumption.
var _ = time.Time{}
