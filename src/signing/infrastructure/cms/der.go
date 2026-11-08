// Package cms builds CMS SignedData structures (RFC 5652) by hand.
//
// Why not a library: CAdES-T needs an unsigned attribute carrying the RFC 3161
// token, and that token can only be requested once the signature value exists.
// Every Go CMS library we evaluated sets unsigned attributes at signing time,
// which is a chicken-and-egg problem. Writing the DER ourselves is ~250 lines
// and gives byte-level control over signedAttrs, which is what validators
// actually check.
package cms

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// Well-known object identifiers.
var (
	OIDData                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	OIDTimeStampToken       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	OIDSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDSHA256WithECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSHA384WithECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSHA512WithECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// ErrEmptyContent means there is nothing to sign.
var ErrEmptyContent = errors.New("cms: content is empty")

// Attribute is a CMS attribute: an OID plus the DER of its single value.
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value []byte
}

// der writes DER by hand. Primitive length encoding and definite lengths are
// all CMS needs, and doing it explicitly keeps the byte layout auditable.
type der struct {
	buf []byte
}

func (d *der) raw(chunk []byte) { d.buf = append(d.buf, chunk...) }

// tag writes a tag-length-value where the value is already DER.
func (d *der) tag(tag byte, value []byte) {
	d.buf = append(d.buf, tag)
	d.buf = append(d.buf, encodeLength(len(value))...)
	d.buf = append(d.buf, value...)
}

// seq wraps a concatenation of DER elements in a SEQUENCE.
func (d *der) seq(elements ...[]byte) []byte {
	return d.tagged(0x30, elements...)
}

// set wraps elements in a SET OF, which DER requires to be sorted.
func (d *der) set(elements ...[]byte) []byte {
	return d.tagged(0x31, elements...)
}

func (d *der) tagged(tag byte, elements ...[]byte) []byte {
	body := d.concat(elements...)
	out := make([]byte, 0, len(body)+6)
	out = append(out, tag)
	out = append(out, encodeLength(len(body))...)
	out = append(out, body...)
	return out
}

func (d *der) concat(elements ...[]byte) []byte {
	size := 0
	for _, element := range elements {
		size += len(element)
	}
	joined := make([]byte, 0, size)
	for _, element := range elements {
		joined = append(joined, element...)
	}
	return joined
}

// octetString encodes an OCTET STRING.
func (d *der) octetString(value []byte) []byte { return d.tagged(0x04, value) }

// integer encodes a small non-negative INTEGER.
func (d *der) integer(value int) []byte {
	bytes := []byte{byte(value)}
	if value > 0x7f {
		bytes = append([]byte{0x00}, bytes...)
	}
	return d.tagged(0x02, bytes)
}

// oid encodes an OBJECT IDENTIFIER.
func (d *der) oid(identifier asn1.ObjectIdentifier) []byte {
	encoded, err := asn1.Marshal(identifier)
	if err != nil {
		// ObjectIdentifiers are constants in this package: an error here is a
		// programming mistake, and failing loudly beats emitting bad DER.
		panic(fmt.Sprintf("cms: cannot encode OID %v: %v", identifier, err))
	}
	return encoded
}

// null encodes the ASN.1 NULL used by RSA AlgorithmIdentifiers.
func (d *der) null() []byte { return []byte{0x05, 0x00} }

// utcTime encodes a UTCTime, which CMS uses for signing time.
func (d *der) utcTime(value string) []byte { return d.tagged(0x17, []byte(value)) }

// encodeLength emits a DER definite length.
func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var bytes []byte
	for remaining := length; remaining > 0; remaining >>= 8 {
		bytes = append([]byte{byte(remaining & 0xff)}, bytes...)
	}
	return append([]byte{0x80 | byte(len(bytes))}, bytes...)
}

// sortSet applies DER's SET OF ordering: shorter encodings first, then
// lexicographic byte order. Validators reject unsorted sets.
func sortSet(elements [][]byte) [][]byte {
	ordered := make([][]byte, len(elements))
	copy(ordered, elements)
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && lessDER(ordered[j], ordered[j-1]); j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	return ordered
}

func lessDER(left, right []byte) bool {
	if len(left) != len(right) {
		return len(left) < len(right)
	}
	for i := range left {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return false
}

// OIDRevocationValues is the CAdES unsigned attribute carrying revocation data.
//
// ETSI EN 319 122-1 defines it as an unsigned attribute of the SignerInfo, which
// is what makes a signature CAdES-LT: the OCSP responses and CRLs needed to check
// it travel with it, outside the signed bytes.
//
// 1.2.840.113549.1.9.16.2.24. The neighbouring .23 is id-aa-ets-certValues, a
// different attribute; using it produced a container that OpenSSL parsed and
// labelled "certValues" while carrying OCSP responses, which is worse than a
// failure because it looks correct.
var OIDRevocationValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 24}

// OIDCertificateValues carries the certificates needed to validate a signature.
//
// Kept for completeness: a full CAdES-LT embeds both. Only the revocation half is
// written today, because the signing certificate chain already travels inside the
// SignedData.
var OIDCertificateValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 23}

// OIDArchiveTimeStampV3 is the CAdES archive timestamp attribute.
//
// ETSI EN 319 122-1: the token covers the encapContentInfo, the certificates
// referenced by the signature, and every unsigned attribute added so far,
// including the revocation material. It is what makes CAdES-LTA: the proof of the
// validation data's state travels inside the same sealed bytes.
var OIDArchiveTimeStampV3 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 48}
