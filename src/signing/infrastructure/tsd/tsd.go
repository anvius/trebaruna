// Package tsd reads and writes time-stamped data (RFC 5544): a document and the
// timestamp tokens that prove it existed, in one file. Italian offices receive
// them as name.pdf.p7m.tsd ("marca temporale" kept with the document).
package tsd

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/ber"
)

// OID is id-ct-timestampedData.
var OID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 31}

// ErrNotTimeStampedData means the bytes are not an RFC 5544 structure.
var ErrNotTimeStampedData = errors.New("not time-stamped data (RFC 5544)")

// Document is a decoded TimeStampedData.
type Document struct {
	// Content is the time-stamped document; empty when only DataURI points
	// at it.
	Content []byte
	DataURI string
	// FileName and MediaType come from the unsigned metadata.
	FileName  string
	MediaType string
	// HashProtected says the metadata is part of what the first token covers.
	HashProtected bool
	metaData      []byte
	// Evidence holds each TimeStampAndCRL as encoded, Tokens the
	// TimeStampToken inside each: the first covers the data, every later one
	// renews the previous element.
	Evidence [][]byte
	Tokens   [][]byte
}

// Covered returns the bytes the token at index proves: the content (after
// the metadata when it is hash-protected) for the first, the previous
// TimeStampAndCRL for a renewal (RFC 5544, sections 2.1 and 4.2).
func (d Document) Covered(index int) []byte {
	if index > 0 {
		return d.Evidence[index-1]
	}
	if d.HashProtected {
		return append(append([]byte{}, d.metaData...), d.Content...)
	}
	return d.Content
}

// Encode builds a TimeStampedData holding the content and one token, with
// the file name and media type as unprotected metadata.
func Encode(content []byte, fileName, mediaType string, token []byte) ([]byte, error) {
	var metaFields []byte
	falseValue, _ := asn1.Marshal(false)
	metaFields = append(metaFields, falseValue...)
	if fileName != "" {
		name, err := asn1.MarshalWithParams(fileName, "utf8")
		if err != nil {
			return nil, err
		}
		metaFields = append(metaFields, name...)
	}
	if mediaType != "" {
		media, err := asn1.MarshalWithParams(mediaType, "ia5")
		if err != nil {
			return nil, err
		}
		metaFields = append(metaFields, media...)
	}

	version, _ := asn1.Marshal(1)
	octets, _ := asn1.Marshal(content)
	evidence := element(asn1.ClassUniversal, asn1.TagSequence, true, token) // TimeStampAndCRL
	body := bytes.Join([][]byte{
		version,
		element(asn1.ClassUniversal, asn1.TagSequence, true, metaFields), // MetaData
		octets,
		element(asn1.ClassContextSpecific, 0, true, evidence), // tstEvidence [0] IMPLICIT
	}, nil)

	return contentInfo(element(asn1.ClassUniversal, asn1.TagSequence, true, body)), nil
}

// contentInfo wraps a TimeStampedData in ContentInfo { OID, [0] EXPLICIT }.
// asn1.Marshal writes a pre-encoded value as it is, without the explicit
// tag, so the wrapper is built by hand.
func contentInfo(timeStampedData []byte) []byte {
	oid, _ := asn1.Marshal(OID)
	return element(asn1.ClassUniversal, asn1.TagSequence, true,
		append(oid, element(asn1.ClassContextSpecific, 0, true, timeStampedData)...))
}

// Renew appends a TimeStampAndCRL holding token to an encoded document; the
// token must cover the last element of its evidence (Document.Covered).
func Renew(data, token []byte) ([]byte, error) {
	if _, err := Decode(data); err != nil {
		return nil, err
	}
	sequence, err := unwrap(data)
	if err != nil {
		return nil, err
	}
	item := element(asn1.ClassUniversal, asn1.TagSequence, true, token)
	var fields []byte
	for rest := sequence.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return nil, err
		}
		if field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
			fields = append(fields, element(asn1.ClassContextSpecific, 0, true, append(field.Bytes, item...))...)
			continue
		}
		fields = append(fields, field.FullBytes...)
	}
	return contentInfo(element(asn1.ClassUniversal, asn1.TagSequence, true, fields)), nil
}

// Is reports whether the bytes are time-stamped data.
func Is(data []byte) bool {
	_, err := unwrap(data)
	return err == nil
}

// unwrap returns the TimeStampedData sequence inside ContentInfo
// { OID, [0] EXPLICIT TimeStampedData }, always in DER: some tools write BER
// with indefinite lengths, and a renewal token covers the DER of the element
// before it.
func unwrap(data []byte) (asn1.RawValue, error) {
	if converted, err := ber.ToDER(data); err == nil {
		data = converted
	}
	var outer struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}
	if _, err := asn1.Unmarshal(data, &outer); err != nil || !outer.Type.Equal(OID) {
		return asn1.RawValue{}, ErrNotTimeStampedData
	}
	if outer.Content.Class != asn1.ClassContextSpecific || outer.Content.Tag != 0 {
		return asn1.RawValue{}, fmt.Errorf("%w: no [0] content", ErrNotTimeStampedData)
	}
	var sequence asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &sequence); err != nil || sequence.Tag != asn1.TagSequence {
		return asn1.RawValue{}, fmt.Errorf("%w: no TimeStampedData sequence", ErrNotTimeStampedData)
	}
	return sequence, nil
}

// Decode reads a TimeStampedData.
func Decode(data []byte) (Document, error) {
	sequence, err := unwrap(data)
	if err != nil {
		return Document{}, err
	}

	var document Document
	var version int
	rest, err := asn1.Unmarshal(sequence.Bytes, &version)
	if err != nil || version != 1 {
		return Document{}, fmt.Errorf("%w: version %d", ErrNotTimeStampedData, version)
	}
	for len(rest) > 0 {
		var field asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return Document{}, fmt.Errorf("%w: %v", ErrNotTimeStampedData, err)
		}
		switch {
		case field.Class == asn1.ClassUniversal && field.Tag == asn1.TagIA5String:
			document.DataURI = string(field.Bytes)
		case field.Class == asn1.ClassUniversal && field.Tag == asn1.TagSequence:
			if err := document.readMetaData(field); err != nil {
				return Document{}, err
			}
		case field.Class == asn1.ClassUniversal && field.Tag == asn1.TagOctetString:
			document.Content = field.Bytes
		case field.Class == asn1.ClassContextSpecific && field.Tag == 0:
			if err := document.readEvidence(field.Bytes); err != nil {
				return Document{}, err
			}
		case field.Class == asn1.ClassContextSpecific:
			return Document{}, fmt.Errorf("%w: only timestamp-token evidence is supported, not [%d]", ErrNotTimeStampedData, field.Tag)
		}
	}
	if len(document.Tokens) == 0 {
		return Document{}, fmt.Errorf("%w: no timestamp token", ErrNotTimeStampedData)
	}
	return document, nil
}

// readMetaData reads hashProtected, fileName and mediaType, keeping the
// encoding for a hash-protected first token.
func (d *Document) readMetaData(field asn1.RawValue) error {
	d.metaData = field.FullBytes
	rest := field.Bytes
	rest, err := asn1.Unmarshal(rest, &d.HashProtected)
	if err != nil {
		return fmt.Errorf("%w: metadata: %v", ErrNotTimeStampedData, err)
	}
	for len(rest) > 0 {
		var value asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &value); err != nil {
			return fmt.Errorf("%w: metadata: %v", ErrNotTimeStampedData, err)
		}
		switch value.Tag {
		case asn1.TagUTF8String:
			d.FileName = string(value.Bytes)
		case asn1.TagIA5String:
			d.MediaType = string(value.Bytes)
		}
	}
	return nil
}

// readEvidence reads each TimeStampAndCRL and the token in it.
func (d *Document) readEvidence(elements []byte) error {
	for len(elements) > 0 {
		var item asn1.RawValue
		var err error
		if elements, err = asn1.Unmarshal(elements, &item); err != nil {
			return fmt.Errorf("%w: evidence: %v", ErrNotTimeStampedData, err)
		}
		var token asn1.RawValue
		if _, err := asn1.Unmarshal(item.Bytes, &token); err != nil {
			return fmt.Errorf("%w: evidence without a token", ErrNotTimeStampedData)
		}
		d.Evidence = append(d.Evidence, item.FullBytes)
		d.Tokens = append(d.Tokens, token.FullBytes)
	}
	return nil
}

// TokenOf returns the TimeStampToken inside a TimeStampResp (a .tsr).
func TokenOf(response []byte) ([]byte, error) {
	var parsed struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(response, &parsed); err != nil {
		return nil, fmt.Errorf("not a timestamp response: %w", err)
	}
	if len(parsed.Token.FullBytes) == 0 {
		return nil, errors.New("the timestamp response carries no token")
	}
	return parsed.Token.FullBytes, nil
}

// element encodes one DER element.
func element(class, tag int, constructed bool, body []byte) []byte {
	encoded, _ := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: constructed, Bytes: body})
	return encoded
}
