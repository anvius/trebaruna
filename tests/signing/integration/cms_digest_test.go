package integration_test

// A signature over a digest computed elsewhere (afirma://
// precalculatedHashAlgorithm): openssl checks it against the document whose
// digest was given, detached.

import (
	"context"
	"crypto"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
)

func TestASignatureOverADigestVerifiesAgainstTheDocument(t *testing.T) {
	fixture := newFixture(t)
	document := []byte("Contenuto firmato per impronta\n")
	documentPath := filepath.Join(fixture.directory, "document.txt")
	if err := os.WriteFile(documentPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		hasher := hash.New()
		hasher.Write(document)
		signature, err := cms.Sign(cms.Request{Certificate: fixture.cert, Signer: fixture.key, IncludeSigningTime: true,
			Hash: hash, ContentDigest: hasher.Sum(nil)})
		if err != nil {
			t.Fatalf("%v: %v", hash, err)
		}
		signaturePath := filepath.Join(fixture.directory, "digest.p7s")
		if err := os.WriteFile(signaturePath, signature.DER, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("openssl", "cms", "-verify", "-in", signaturePath, "-inform", "DER", "-binary",
			"-content", documentPath, "-CAfile", fixture.certPath, "-purpose", "any", "-out", os.DevNull).CombinedOutput()
		if err != nil {
			t.Errorf("%v: openssl rejected the signature: %v\n%s", hash, err, output)
		}
	}

	digest := make([]byte, 32)
	for name, request := range map[string]cms.Request{
		"embedded":     {Certificate: fixture.cert, Signer: fixture.key, ContentDigest: digest, EmbeddedContent: true},
		"wrong length": {Certificate: fixture.cert, Signer: fixture.key, ContentDigest: digest, Hash: crypto.SHA512},
		"SHA-1":        {Certificate: fixture.cert, Signer: fixture.key, Content: document, Hash: crypto.SHA1},
	} {
		if _, err := cms.Sign(request); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// TestADigestIsSignedOnceAndNotArchived: a digest is not co- or
// counter-signed, and the archive timestamp, which seals the document, is
// refused before any authority is asked.
func TestADigestIsSignedOnceAndNotArchived(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	sum := sha256.Sum256([]byte("acta"))
	digest, err := domain.NewContentDigest("SHA-256", sum[:])
	if err != nil {
		t.Fatal(err)
	}
	cades := infrastructure.NewCadesSigner(nil)
	if signed, err := cades.SignCades(context.Background(), application.CadesRequest{ContentDigest: digest, Signer: signer, Level: domain.BES}); err != nil || len(signed) == 0 {
		t.Fatalf("a digest signs: %v", err)
	}
	for name, test := range map[string]struct {
		request application.CadesRequest
		reason  string
	}{
		"co-signed": {application.CadesRequest{ContentDigest: digest, Signer: signer, Level: domain.BES, Cosign: true, Content: []byte{0x30}},
			"a digest is signed, not co-"},
		"archival": {application.CadesRequest{ContentDigest: digest, Signer: signer, Level: domain.LTA, TimestampURL: "http://tsa.invalid"},
			"only its digest is here"},
	} {
		if _, err := cades.SignCades(context.Background(), test.request); err == nil || !strings.Contains(err.Error(), test.reason) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
