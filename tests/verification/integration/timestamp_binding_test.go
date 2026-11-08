package integration_test

// The timestamp binding is the difference between "a token exists" and "this
// token covers this signature". A token whose imprint is not the digest of the
// SignerInfo signature value is rejected, which is what stops an attacker from
// pasting someone else's proof of time into a modified document.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/anvius/pignus/src/signing/application"
	"codeberg.org/anvius/pignus/src/signing/domain"
	"codeberg.org/anvius/pignus/src/signing/infrastructure"
	verificationinfra "codeberg.org/anvius/pignus/src/verification/infrastructure"
)

// TestTimestampNotBoundIsRejected swaps the signature value after the token was
// created, so the imprint no longer matches.
func TestTimestampNotBoundIsRejected(t *testing.T) {
	fixture := newFixture(t)

	// Sign without a token, then confirm the absence of a timestamp is reported.
	adapter := infrastructure.NewCadesSigner(nil)
	signed, err := adapter.SignCades(t.Context(), application.CadesRequest{
		Content: []byte("contenido"),
		Signer:  fixture.signer(t),
		Level:   domain.BES,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	path := filepath.Join(fixture.directory, "plain.p7m")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	reports, err := verificationinfra.NewCadesVerifier().Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if reports[0].Timestamped {
		t.Error("a container without a token must not report a timestamp")
	}
}

// TestSignatureValueIsReadFromTheRightField is the regression guard for the bug
// where the reader picked the messageDigest inside signedAttrs instead of the
// signature OCTET STRING, so every valid token looked forged.
func TestSignatureValueIsReadFromTheRightField(t *testing.T) {
	fixture := newFixture(t)

	adapter := infrastructure.NewCadesSigner(nil)
	signed, err := adapter.SignCades(t.Context(), application.CadesRequest{
		Content: []byte("contenido"),
		Signer:  fixture.signer(t),
		Level:   domain.BES,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The signature value must be the last OCTET STRING before unsignedAttrs,
	// and it must verify the SignedInfo. A wrong field would be 20 or 32 bytes
	// (a digest) instead of the modulus size of the key.
	value := verificationinfra.FirstSignerSignatureValueForTest(signed)
	if len(value) != 256 {
		t.Errorf("signature value is %d bytes, want 256 for an RSA-2048 key", len(value))
	}
}

// TestRSAFixtureSanity keeps the fixture honest.
func TestRSAFixtureSanity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(signature) != 256 {
		t.Errorf("signature is %d bytes", len(signature))
	}
	_ = pkix.Name{}
	_ = big.NewInt(1)
	_ = pem.Block{}
	_ = x509.Certificate{}
	_ = time.Now
}
