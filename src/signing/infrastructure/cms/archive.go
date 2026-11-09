package cms

// The archive-time-stamp-v3 of CAdES-A (ETSI EN 319 122-1, 5.5.2 and 5.5.3):
// what its message imprint covers, and the hash index it carries, computed
// once here for the signer that adds it and the verifier that checks it.

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// OIDATSHashIndexV3 is ats-hash-index-v3 (EN 319 122-1, 5.5.2).
var OIDATSHashIndexV3 = asn1.ObjectIdentifier{0, 4, 0, 19122, 1, 5}

// ErrArchiveMismatch means an archive timestamp's hash index lists an
// element the signature no longer has: what it sealed was taken away.
var ErrArchiveMismatch = errors.New("the archive timestamp sealed an element the signature no longer has")

// hashIndex is an ATSHashIndexV3: the hash of each certificate, each
// revocation value and each unsigned attribute value, in the order they
// appear.
type hashIndex struct {
	certificates, crls, unsigned [][]byte
}

// ArchiveTimeStampV3Input returns, for the SignerInfo at index of a CMS
// SignedData, the start of what an archive-time-stamp-v3's message imprint
// covers (EN 319 122-1, 5.5.3: the eContentType, the hash of the signed
// content, the SignerInfo's version, sid, digestAlgorithm, signedAttrs,
// signatureAlgorithm and signature) and the ATSHashIndexV3 of the signature
// as it stands (5.5.2), with hash. The imprint is the digest of the two
// concatenated. detached is the content when the envelope leaves it out.
func ArchiveTimeStampV3Input(contentInfoDER []byte, index int, detached []byte, hash crypto.Hash) (prefix, hashIndexDER []byte, err error) {
	parts, err := splitSignedData(contentInfoDER)
	if err != nil {
		return nil, nil, err
	}
	signers, err := splitSequence(parts.signerInfos)
	if err != nil {
		return nil, nil, err
	}
	if index < 0 || index >= len(signers) {
		return nil, nil, fmt.Errorf("cms: no SignerInfo %d among %d", index, len(signers))
	}
	signerFields, err := splitSequence(signers[index])
	if err != nil || len(signerFields) < 6 {
		return nil, nil, fmt.Errorf("cms: unreadable SignerInfo %d", index)
	}

	content := detached
	if parts.content != nil {
		content = parts.content
	}
	if content == nil {
		return nil, nil, fmt.Errorf("cms: the signed content is needed for an archive timestamp")
	}
	digest := hash.New()
	digest.Write(content)

	var input bytes.Buffer
	input.Write(parts.contentType)
	input.Write(digest.Sum(nil))
	for _, field := range signerFields[:6] {
		input.Write(field)
	}

	indexed, err := indexOf(parts, signerFields, hash)
	if err != nil {
		return nil, nil, err
	}
	return input.Bytes(), indexed.encode(hash), nil
}

// WithArchiveTimeStampV3 adds an archive-time-stamp-v3 to the SignerInfo at
// index: the token, its own SignerInfo carrying the hash index it was
// computed with as ats-hash-index-v3 (an unsigned attribute, outside what the
// authority signed).
func WithArchiveTimeStampV3(contentInfoDER []byte, index int, tokenDER, hashIndexDER []byte) ([]byte, error) {
	token, err := appendUnsignedAttribute(tokenDER, OIDATSHashIndexV3, hashIndexDER)
	if err != nil {
		return nil, fmt.Errorf("cms: add the hash index to the archive timestamp: %w", err)
	}
	return appendUnsignedAttributeTo(contentInfoDER, index, OIDArchiveTimeStampV3, token)
}

// TokenHashIndex reads the ats-hash-index-v3 an archive timestamp token
// carries.
func TokenHashIndex(tokenDER []byte) ([]byte, error) {
	parts, err := splitSignedData(tokenDER)
	if err != nil {
		return nil, err
	}
	signers, err := splitSequence(parts.signerInfos)
	if err != nil || len(signers) != 1 {
		return nil, fmt.Errorf("cms: the timestamp token has no single SignerInfo")
	}
	fields, err := splitSequence(signers[0])
	if err != nil {
		return nil, err
	}
	for _, field := range fields[6:] {
		if field[0] != 0xa1 {
			continue
		}
		_, _, attributes, err := parseTLV(field)
		if err != nil {
			return nil, err
		}
		elements, err := splitElements(attributes)
		if err != nil {
			return nil, err
		}
		for _, attribute := range elements {
			attributeType, values, err := splitAttribute(attribute)
			if err == nil && bytes.Equal(attributeType, atsHashIndexType) && len(values) == 1 {
				return values[0], nil
			}
		}
	}
	return nil, fmt.Errorf("cms: the archive timestamp carries no ats-hash-index-v3")
}

// HashIndexHolds reports whether every element the sealed hash index lists
// is still in the signature, whose current index is current.
func HashIndexHolds(sealedDER, currentDER []byte) error {
	sealed, err := decodeHashIndex(sealedDER)
	if err != nil {
		return err
	}
	current, err := decodeHashIndex(currentDER)
	if err != nil {
		return err
	}
	for _, pair := range [][2][][]byte{{sealed.certificates, current.certificates}, {sealed.crls, current.crls}, {sealed.unsigned, current.unsigned}} {
		for _, wanted := range pair[0] {
			if !slices.ContainsFunc(pair[1], func(have []byte) bool { return bytes.Equal(have, wanted) }) {
				return ErrArchiveMismatch
			}
		}
	}
	return nil
}

// signedDataParts are the fields of a SignedData an archive timestamp reads.
type signedDataParts struct {
	contentType  []byte // the eContentType, tag and length included
	content      []byte // the eContent's octets; nil when detached
	certificates []byte // the [0] certificates, or nil
	crls         []byte // the [1] crls, or nil
	signerInfos  []byte
}

func splitSignedData(contentInfoDER []byte) (signedDataParts, error) {
	contentInfo, err := splitSequence(contentInfoDER)
	if err != nil || len(contentInfo) < 2 {
		return signedDataParts{}, fmt.Errorf("cms: unreadable ContentInfo")
	}
	_, _, signedDataDER, err := parseTLV(contentInfo[1])
	if err != nil {
		return signedDataParts{}, err
	}
	fields, err := splitSequence(signedDataDER)
	if err != nil || len(fields) < 4 {
		return signedDataParts{}, fmt.Errorf("cms: unreadable SignedData")
	}
	encapsulated, err := splitSequence(fields[2])
	if err != nil || len(encapsulated) == 0 {
		return signedDataParts{}, fmt.Errorf("cms: unreadable encapContentInfo")
	}
	parts := signedDataParts{contentType: encapsulated[0], signerInfos: fields[len(fields)-1]}
	if len(encapsulated) > 1 {
		if parts.content, err = explicitOctets(encapsulated[1]); err != nil {
			return signedDataParts{}, err
		}
	}
	for _, field := range fields[3 : len(fields)-1] {
		switch field[0] {
		case 0xa0:
			parts.certificates = field
		case 0xa1:
			parts.crls = field
		}
	}
	return parts, nil
}

// explicitOctets reads a [0] EXPLICIT OCTET STRING.
func explicitOctets(wrapped []byte) ([]byte, error) {
	_, _, inner, err := parseTLV(wrapped)
	if err != nil {
		return nil, err
	}
	return octetStringValue(inner)
}

// octetStringValue is an OCTET STRING's octets, primitive or made of
// segments.
func octetStringValue(encoded []byte) ([]byte, error) {
	tag, _, contents, err := parseTLV(encoded)
	if err != nil {
		return nil, err
	}
	switch tag {
	case 0x04:
		return contents, nil
	case 0x24:
		segments, err := splitElements(contents)
		if err != nil {
			return nil, err
		}
		var joined []byte
		for _, segment := range segments {
			piece, err := octetStringValue(segment)
			if err != nil {
				return nil, err
			}
			joined = append(joined, piece...)
		}
		return joined, nil
	}
	return nil, fmt.Errorf("cms: eContent is not an OCTET STRING")
}

// indexOf hashes what ATSHashIndexV3 lists for a SignerInfo.
func indexOf(parts signedDataParts, signerFields [][]byte, hash crypto.Hash) (hashIndex, error) {
	digest := func(data ...[]byte) []byte {
		hasher := hash.New()
		for _, piece := range data {
			hasher.Write(piece)
		}
		return hasher.Sum(nil)
	}
	var indexed hashIndex
	var err error
	if indexed.certificates, err = elementDigests(parts.certificates, digest); err != nil {
		return hashIndex{}, err
	}
	if indexed.crls, err = elementDigests(parts.crls, digest); err != nil {
		return hashIndex{}, err
	}
	for _, field := range signerFields[6:] {
		if field[0] != 0xa1 {
			continue
		}
		_, _, body, err := parseTLV(field)
		if err != nil {
			return hashIndex{}, err
		}
		attributes, err := splitElements(body)
		if err != nil {
			return hashIndex{}, err
		}
		// One hash per value: the attribute's type and that value.
		for _, attribute := range attributes {
			attributeType, values, err := splitAttribute(attribute)
			if err != nil {
				return hashIndex{}, err
			}
			for _, value := range values {
				indexed.unsigned = append(indexed.unsigned, digest(attributeType, value))
			}
		}
	}
	return indexed, nil
}

// elementDigests hashes each element of a [0] certificates or [1] crls
// field; an absent field has none.
func elementDigests(field []byte, digest func(...[]byte) []byte) ([][]byte, error) {
	if field == nil {
		return nil, nil
	}
	_, _, body, err := parseTLV(field)
	if err != nil {
		return nil, err
	}
	elements, err := splitElements(body)
	if err != nil {
		return nil, err
	}
	digests := make([][]byte, len(elements))
	for index, element := range elements {
		digests[index] = digest(element)
	}
	return digests, nil
}

// splitAttribute is an Attribute's type and its values.
func splitAttribute(attribute []byte) ([]byte, [][]byte, error) {
	fields, err := splitSequence(attribute)
	if err != nil || len(fields) != 2 {
		return nil, nil, fmt.Errorf("cms: unreadable attribute")
	}
	values, err := splitSequence(fields[1])
	if err != nil {
		return nil, nil, err
	}
	return fields[0], values, nil
}

// encode writes the ATSHashIndexV3, its algorithm left out when SHA-256,
// the default.
func (h hashIndex) encode(hash crypto.Hash) []byte {
	encoder := &der{}
	octets := func(hashes [][]byte) []byte {
		elements := make([][]byte, len(hashes))
		for index, value := range hashes {
			elements[index] = encoder.octetString(value)
		}
		return encoder.seq(elements...)
	}
	var fields [][]byte
	if hash != crypto.SHA256 {
		fields = append(fields, encoder.seq(encoder.oid(digestOID(hash))))
	}
	fields = append(fields, octets(h.certificates), octets(h.crls), octets(h.unsigned))
	return encoder.seq(fields...)
}

// decodeHashIndex reads an ATSHashIndexV3.
func decodeHashIndex(encoded []byte) (hashIndex, error) {
	fields, err := splitSequence(encoded)
	if err != nil {
		return hashIndex{}, err
	}
	if len(fields) == 4 {
		fields = fields[1:]
	}
	if len(fields) != 3 {
		return hashIndex{}, fmt.Errorf("cms: unreadable ATSHashIndexV3")
	}
	var lists [3][][]byte
	for position, field := range fields {
		elements, err := splitSequence(field)
		if err != nil {
			return hashIndex{}, err
		}
		for _, element := range elements {
			_, _, value, err := parseTLV(element)
			if err != nil {
				return hashIndex{}, err
			}
			lists[position] = append(lists[position], value)
		}
	}
	return hashIndex{certificates: lists[0], crls: lists[1], unsigned: lists[2]}, nil
}

// digestOID names a digest algorithm.
func digestOID(hash crypto.Hash) asn1.ObjectIdentifier {
	switch hash {
	case crypto.SHA384:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	case crypto.SHA512:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	}
	return OIDSHA256
}

// atsHashIndexType is ats-hash-index-v3's OID as an attribute carries it.
var atsHashIndexType, _ = asn1.Marshal(OIDATSHashIndexV3)
