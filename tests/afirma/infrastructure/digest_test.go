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
	"os"
	"os/exec"
	"path/filepath"
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

// TestAPageSignsAnEncryptedPDFWithItsPassword: AutoFirma's ownerPassword,
// else userPassword, opens the PDF; pdfsig verifies it with the password.
func TestAPageSignsAnEncryptedPDFWithItsPassword(t *testing.T) {
	for _, tool := range []string{"qpdf", "pdfsig"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not available")
		}
	}
	directory := t.TempDir()
	plain := write(t, directory, "plain.pdf", onePagePDF())
	encrypted := filepath.Join(directory, "encrypted.pdf")
	if output, err := exec.Command("qpdf", "--encrypt", "abierto", "propietario", "256", "--", plain, encrypted).CombinedOutput(); err != nil {
		t.Fatalf("qpdf: %v\n%s", err, output)
	}
	content, _ := os.ReadFile(encrypted)
	maria, _ := identity(t, "MARIA GARCIA", 97)
	signer := infrastructure.NewNativePageSigner()
	if _, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Sign, Format: format(t, "PAdES"),
		Algorithm: "SHA256withECDSA", Key: maria, Data: content, Properties: map[string]string{}}); err == nil {
		t.Error("an encrypted PDF signed without its password")
	}
	signed, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Sign, Format: format(t, "PAdES"),
		Algorithm: "SHA256withECDSA", Key: maria, Data: content, Properties: map[string]string{"userPassword": "abierto"}})
	if err != nil {
		t.Fatal(err)
	}
	path := write(t, directory, "signed.pdf", signed.Signature)
	if output, _ := exec.Command("pdfsig", "-upw", "abierto", path).CombinedOutput(); !strings.Contains(string(output), "Signature is Valid") {
		t.Errorf("pdfsig: %s", output)
	}
}
