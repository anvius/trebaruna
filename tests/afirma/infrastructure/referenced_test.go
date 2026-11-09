package infrastructure_test

// XAdES Externally Detached and useManifest: the documents stay where the
// page says, the signature covers them by address and digest, and the
// approval lists both.

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	"codeberg.org/simplicer/trebaruna/tests/support/afirmaserver"
)

func checkPageSignature(t *testing.T, signed []byte, resolve xmldsig.Resolver) (*etree.Document, error) {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	signature := document.FindElement("//Signature")
	der, _ := base64.StdEncoding.DecodeString(signature.FindElement(".//X509Certificate").Text())
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return document, xmldsig.Check(document, signature, parsed.PublicKey, resolve)
}

func TestAPageSignsDocumentsItNamesByAddress(t *testing.T) {
	maria, _ := identity(t, "MARIA GARCIA", 95)
	signer := infrastructure.NewNativePageSigner()
	document := []byte("%PDF-1.7 solicitud")
	sum := sha512.Sum512(document)

	// Externally Detached: the data are the document's SHA-512, AutoFirma's default.
	signed, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Sign, Format: format(t, "XAdES"),
		Algorithm: "SHA256withECDSA", Key: maria, Data: sum[:],
		Properties: map[string]string{"format": "XAdES Externally Detached", "uri": "https://sede.example/solicitud.pdf"}})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(uri string) ([]byte, error) {
		if uri == "https://sede.example/solicitud.pdf" {
			return document, nil
		}
		return nil, xmldsig.ErrContentMissing
	}
	if _, err := checkPageSignature(t, signed.Signature, resolve); err != nil {
		t.Errorf("with the document, the signature verifies: %v", err)
	}

	// useManifest with two documents, their SHA-256 digests in md1 and md2.
	first, second := sha256.Sum256([]byte("uno")), sha256.Sum256([]byte("dos"))
	signed, err = signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Sign, Format: format(t, "XAdES"),
		Algorithm: "SHA256withECDSA", Key: maria,
		Properties: map[string]string{"useManifest": "true", "precalculatedHashAlgorithm": "SHA-256",
			"uri1": "https://sede.example/uno", "md1": base64.StdEncoding.EncodeToString(first[:]),
			"uri2": "https://sede.example/dos", "md2": base64.StdEncoding.EncodeToString(second[:])}})
	if err != nil {
		t.Fatal(err)
	}
	tree, err := checkPageSignature(t, signed.Signature, nil)
	if err != nil {
		t.Errorf("the manifest signature verifies: %v", err)
	}
	references := tree.FindElements("//Manifest/Reference")
	if len(references) != 2 || references[1].FindElement("DigestValue").Text() != base64.StdEncoding.EncodeToString(second[:]) {
		t.Errorf("the manifest holds both digests: %d references", len(references))
	}

	for name, test := range map[string]struct {
		request application.PageSignature
		want    domain.FailureCode
	}{
		"a document, not a digest": {application.PageSignature{Crypto: domain.Sign, Data: document,
			Properties: map[string]string{"format": "XAdES Externally Detached", "uri": "https://sede.example/x"}}, domain.Params},
		"SHA-1": {application.PageSignature{Crypto: domain.Sign, Data: make([]byte, 20),
			Properties: map[string]string{"useManifest": "true", "uri": "https://sede.example/x", "precalculatedHashAlgorithm": "SHA-1"}}, domain.Params},
		"co-signature": {application.PageSignature{Crypto: domain.Cosign, Data: []byte("<a/>"),
			Properties: map[string]string{"useManifest": "true", "uri": "https://sede.example/x"}}, domain.UnsupportedOperation},
	} {
		test.request.Format, test.request.Algorithm, test.request.Key = format(t, "XAdES"), "SHA256withECDSA", maria
		_, err := signer.Sign(context.Background(), test.request)
		if failure, ok := err.(domain.Failure); !ok || failure.Code != test.want {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTheApprovalListsTheDocumentsByAddressAndDigest.
func TestTheApprovalListsTheDocumentsByAddressAndDigest(t *testing.T) {
	server := afirmaserver.New(t)
	maria, _ := identity(t, "MARIA GARCIA", 96)
	digest := sha512.Sum512([]byte("anexo"))
	approver := &recordingApprover{approving: approving{key: maria}}
	id, key := sessionID(), "11223344"
	if _, err := useCase(server, approver).Execute(context.Background(),
		bareRequest(t, id, key, "sign", "XAdES", "SHA256withECDSA", "useManifest=true\nuri=https://sede.example/anexo.pdf", digest[:])); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(approver.proposal.Warnings, func(warning string) bool {
		return strings.Contains(warning, "https://sede.example/anexo.pdf (SHA-512 "+hex.EncodeToString(digest[:])+")")
	}) {
		t.Errorf("the approval does not list the document: %v", approver.proposal.Warnings)
	}

	// An invalid list is refused before anyone is asked.
	refused := &recordingApprover{approving: approving{key: maria}}
	id = sessionID()
	useCase(server, refused).Execute(context.Background(), bareRequest(t, id, key, "sign", "XAdES", "SHA256withECDSA", "useManifest=true", digest[:]))
	if history := server.History(id); len(history) == 0 || !strings.HasPrefix(history[len(history)-1], "SAF_03") || len(refused.proposal.Warnings) != 0 {
		t.Errorf("an empty manifest reached the person or was not refused: %v", history)
	}
}
