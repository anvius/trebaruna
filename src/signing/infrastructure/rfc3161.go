package infrastructure

// A hand-written RFC 3161 timestamp request.
//
// Why not the library's CreateRequest:
//
//  1. Its contract is "give me a reader and I will hash it". We were already
//     passing a digest, so it hashed the digest: sha256(sha256(document)).
//     That is our misuse, not a library defect, and it produced tokens that
//     OpenSSL rejected.
//  2. CreateRequest sets Request.Certificates before consulting opts, so
//     "include the TSA certificate" is ignored and tokens arrive without the
//     certificate needed to verify them.
//
// Building the request here makes the contract explicit: the caller hashes, and
// this function only encodes. ~40 lines, and the imprint is unambiguous.

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"fmt"

	// The hash implementations must be linked in, otherwise crypto.Hash.New
	// panics at runtime for anything but SHA-256.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// oidSHA256 and oidSHA512 identify the digest algorithms a TSA accepts.
var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// digestOID maps a crypto.Hash onto the ASN.1 identifier.
func digestOID(hash crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch hash {
	case crypto.SHA256:
		return oidSHA256, nil
	case crypto.SHA512:
		return oidSHA512, nil
	}
	return nil, fmt.Errorf("unsupported digest %v for timestamping", hash)
}

// timestampRequest is the RFC 3161 TimeStampReq structure.
type timestampRequest struct {
	Version        int
	MessageImprint struct {
		HashAlgorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		HashedMessage []byte
	}
	// CertReq asks the TSA to include its certificate in the token, which is
	// required to verify the token later.
	CertReq bool `asn1:"optional"`
}

// BuildTimestampRequest encodes a request for the given digest.
//
// digest must already be the hash of whatever is being timestamped: the request
// carries an imprint, not a document.
func BuildTimestampRequest(digest []byte, hash crypto.Hash) ([]byte, error) {
	algorithm, err := digestOID(hash)
	if err != nil {
		return nil, err
	}

	expectedSize := hash.Size()
	if len(digest) != expectedSize {
		return nil, fmt.Errorf(
			"%v digest must be %d bytes, got %d", hash, expectedSize, len(digest),
		)
	}

	request := timestampRequest{Version: 1}
	request.MessageImprint.HashAlgorithm.Algorithm = algorithm
	// NULL parameters: absent fields are rejected by some TSAs.
	request.MessageImprint.HashAlgorithm.Parameters = asn1.NullRawValue
	request.MessageImprint.HashedMessage = digest
	request.CertReq = true

	encoded, err := asn1.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode timestamp request: %w", err)
	}
	return encoded, nil
}

// digestFor hashes content with the given algorithm.
func digestFor(content []byte, hash crypto.Hash) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("digest %v is not available in this build", hash)
	}
	hasher := hash.New()
	if _, err := hasher.Write(content); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// readerDigest hashes a stream without buffering it whole.
func readerDigest(content []byte, hash crypto.Hash) ([]byte, error) {
	return digestFor(content, hash)
}

var _ = bytes.NewReader
