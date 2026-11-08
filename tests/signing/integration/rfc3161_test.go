package integration_test

// The RFC 3161 request is hand-written because the library's CreateRequest
// hashes the input in blocks of the digest size, producing an imprint of
// digests that no other implementation can verify. These tests pin the format.

import (
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"testing"

	"codeberg.org/anvius/trebaruna/src/signing/infrastructure"
)

// TestTimestampRequestCarriesTheDigestUnchanged is the regression guard: the
// imprint in the request must be the digest of the document, byte for byte.
func TestTimestampRequestCarriesTheDigestUnchanged(t *testing.T) {
	document := []byte("contratto")
	digest := sha256.Sum256(document)

	encoded, err := infrastructure.BuildTimestampRequest(digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("BuildTimestampRequest: %v", err)
	}

	var request struct {
		Version        int
		MessageImprint struct {
			HashAlgorithm struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			HashedMessage []byte
		}
		CertReq bool `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(encoded, &request); err != nil {
		t.Fatalf("decode request: %v", err)
	}

	if request.Version != 1 {
		t.Errorf("version = %d, want 1", request.Version)
	}
	if string(request.MessageImprint.HashedMessage) != string(digest[:]) {
		t.Errorf("imprint is not the document digest:\n got %x\nwant %x",
			request.MessageImprint.HashedMessage, digest)
	}
	if !request.MessageImprint.HashAlgorithm.Algorithm.Equal(
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}) {
		t.Errorf("algorithm = %v, want SHA-256", request.MessageImprint.HashAlgorithm.Algorithm)
	}
	if !request.CertReq {
		t.Error("CertReq must be set, or the token arrives without the TSA certificate")
	}
}

// TestTimestampRequestRejectsWrongDigestLength catches a mismatched hash and
// digest, which would be accepted by a naive encoder.
func TestTimestampRequestRejectsWrongDigestLength(t *testing.T) {
	if _, err := infrastructure.BuildTimestampRequest([]byte("short"), crypto.SHA256); err == nil {
		t.Fatal("a 5-byte SHA-256 digest must be rejected")
	}
}

// TestTimestampRequestSupportsSHA512: TSAs may require a stronger digest.
func TestTimestampRequestSupportsSHA512(t *testing.T) {
	digest := make([]byte, 64)
	if _, err := infrastructure.BuildTimestampRequest(digest, crypto.SHA512); err != nil {
		t.Fatalf("SHA-512 must be supported: %v", err)
	}
}
