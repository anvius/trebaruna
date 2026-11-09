package domain_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// TestADigestIsTakenWithItsAlgorithm: the names a site writes, the length
// each algorithm gives, and SHA-1 refused.
func TestADigestIsTakenWithItsAlgorithm(t *testing.T) {
	sha256Digest := sha256.Sum256([]byte("documento"))
	sha384Digest := sha512.Sum384([]byte("documento"))
	for name, test := range map[string]struct {
		algorithm string
		value     []byte
		want      string
	}{
		"SHA-256": {"SHA-256", sha256Digest[:], "SHA256"},
		"SHA256":  {"sha256", sha256Digest[:], "SHA256"},
		"XML URI": {"http://www.w3.org/2001/04/xmldsig-more#sha384", sha384Digest[:], "SHA384"},
		"SHA-512": {"SHA-512", make([]byte, 64), "SHA512"},
	} {
		digest, err := domain.NewContentDigest(test.algorithm, test.value)
		if err != nil || digest.Algorithm() != test.want || string(digest.Value()) != string(test.value) || digest.IsZero() {
			t.Errorf("%s: %q, %v", name, digest.Algorithm(), err)
		}
	}
	for name, test := range map[string]struct {
		algorithm string
		value     []byte
	}{
		"SHA-1":        {"SHA-1", make([]byte, 20)},
		"unknown":      {"MD5", make([]byte, 16)},
		"short":        {"SHA-256", sha256Digest[:31]},
		"a whole file": {"SHA-256", []byte("a document, not its digest, sent by mistake")},
	} {
		if _, err := domain.NewContentDigest(test.algorithm, test.value); !errors.Is(err, domain.ErrInvalidContentDigest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !(domain.ContentDigest{}).IsZero() {
		t.Error("no digest")
	}
}
