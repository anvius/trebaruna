//go:build cgo

package infrastructure_test

// An AutoFirma batch signed with a key that never leaves the card: the
// pre-signatures are signed on the token (PKCS#1 v1.5 with SHA-256) and the
// site's post-signer verifies each one.

import (
	"context"
	"encoding/base64"
	"net/url"
	"slices"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	afirmainfra "codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/tests/support/afirmaserver"
)

type cardApprover struct{ key signing.Signer }

func (c cardApprover) Approve(context.Context, application.Proposal) (application.Decision, error) {
	return application.Decision{Approved: true, Key: c.key}, nil
}

func TestACardSignsAnAfirmaBatch(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")
	key, err := signing.NewSigner(signing.NameFromCertificate, signing.FromToken, signing.WithToken(token.module, token.label, token.pin))
	if err != nil {
		t.Fatal(err)
	}
	server := afirmaserver.New(t)
	outcome := server.EnableBatches()
	courier := afirmainfra.WithClient(server.Client())
	use := application.NewAnswerPage(cardApprover{key: key}, afirmainfra.NewNativePageSigner(), afirmainfra.KeyCertificates{},
		afirmainfra.WebData{}, afirmainfra.LocalFiles{}, courier, courier).
		WithBatches(afirmainfra.BatchServices{Client: server.Client()}, afirmainfra.KeyRawSigner{})

	batch := `{"algorithm":"SHA256withRSA","format":"CAdES","singlesigns":[{"id":"doc1","datareference":"r1"},{"id":"doc2","datareference":"r2"}]}`
	uri := "afirma://batch?batchpresignerurl=" + url.QueryEscape("http://sede.example/JSONBatchPresigner") +
		"&batchpostsignerurl=" + url.QueryEscape("http://sede.example/JSONBatchPostsigner") +
		"&jsonbatch=true&needcert=true&dat=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(batch)))
	invocation, _ := domain.ParseInvocation(uri)
	if _, err := use.Execute(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(outcome.Verified, []string{"doc1", "doc2"}) {
		t.Fatalf("the post-signer verified %v (failed %v)", outcome.Verified, outcome.Failed)
	}
}
