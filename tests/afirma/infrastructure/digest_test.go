package infrastructure_test

// precalculatedHashAlgorithm: the page sends the document's digest, and
// the CAdES signature is made over it, detached. openssl checks it against
// the document itself.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	"codeberg.org/simplicer/trebaruna/tests/support/afirmaserver"
)

func TestADigestThePageComputedIsSignedDetached(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	document := []byte("modelo 303, tercer trimestre\n")
	directory := t.TempDir()
	documentPath := write(t, directory, "document", document)
	sha256Digest, sha512Digest := sha256.Sum256(document), sha512.Sum512(document)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaSigner, _ := identityWith(t, rsaKey, "MARIA GARCIA", 91)
	ecSigner, _ := identityWith(t, ecKey, "MARIA GARCIA", 92)
	signer := infrastructure.NewNativePageSigner()
	for name, test := range map[string]struct {
		request application.PageSignature
	}{
		"RSA, SHA-256": {application.PageSignature{Algorithm: "SHA256withRSA", Key: rsaSigner, Data: sha256Digest[:],
			Properties: map[string]string{"precalculatedHashAlgorithm": "SHA-256"}}},
		"ECDSA, SHA-512, mode ignored": {application.PageSignature{Algorithm: "SHA512withECDSA", Key: ecSigner, Data: sha512Digest[:],
			Properties: map[string]string{"precalculatedHashAlgorithm": "SHA-512", "mode": "implicit"}}},
	} {
		test.request.Crypto, test.request.Format = domain.Sign, format(t, "CAdES")
		signed, err := signer.Sign(context.Background(), test.request)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		opensslVerify(t, "-in", write(t, directory, "digest.p7s", signed.Signature), "-content", documentPath, "-binary")
	}

	for name, test := range map[string]struct {
		request application.PageSignature
		want    domain.FailureCode
	}{
		"another algorithm": {application.PageSignature{Crypto: domain.Sign, Format: format(t, "CAdES"), Algorithm: "SHA256withRSA",
			Data: sha512Digest[:], Properties: map[string]string{"precalculatedHashAlgorithm": "SHA-512"}}, domain.Params},
		"not a digest": {application.PageSignature{Crypto: domain.Sign, Format: format(t, "CAdES"), Algorithm: "SHA256withRSA",
			Data: document, Properties: map[string]string{"precalculatedHashAlgorithm": "SHA-256"}}, domain.Params},
		// The data look like an envelope, as a co-signature's must.
		"co-signature": {application.PageSignature{Crypto: domain.Cosign, Format: format(t, "CAdES"), Algorithm: "SHA256withRSA",
			Data: append([]byte{0x30}, sha256Digest[:31]...), Properties: map[string]string{"precalculatedHashAlgorithm": "SHA-256"}}, domain.UnsupportedOperation},
		"a PDF": {application.PageSignature{Crypto: domain.Sign, Format: format(t, "PAdES"), Algorithm: "SHA256withRSA",
			Data: onePagePDF(), Properties: map[string]string{"precalculatedHashAlgorithm": "SHA-256"}}, domain.UnsupportedOperation},
	} {
		test.request.Key = rsaSigner
		_, err := signer.Sign(context.Background(), test.request)
		if failure, ok := err.(domain.Failure); !ok || failure.Code != test.want {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTheApprovalShowsTheDigestThePageSent: the person can compare it with
// the document's, if they have it.
func TestTheApprovalShowsTheDigestThePageSent(t *testing.T) {
	server := afirmaserver.New(t)
	maria, _ := identity(t, "MARIA GARCIA", 93)
	digest := sha256.Sum256([]byte("modelo 303"))
	approver := &recordingApprover{approving: approving{key: maria}}
	id, key := sessionID(), "11223344"
	if _, err := useCase(server, approver).Execute(context.Background(),
		bareRequest(t, id, key, "sign", "CAdES", "SHA256withECDSA", "precalculatedHashAlgorithm=SHA-256", digest[:])); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(approver.proposal.Warnings, func(warning string) bool {
		return strings.Contains(warning, "SHA-256 digest of a document, "+hex.EncodeToString(digest[:])+", not the document")
	}) {
		t.Errorf("the approval does not show the digest: %v", approver.proposal.Warnings)
	}
}
