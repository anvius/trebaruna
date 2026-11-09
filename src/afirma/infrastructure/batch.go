package infrastructure

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
	signinfra "codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	ledger "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// BatchServices posts to a site's batch pre- and post-signers (E.3): the
// batch re-encoded URL-safe, the certificate chain, and the triphase data.
type BatchServices struct {
	Client *http.Client
}

// NewBatchServices builds the client over the connection record.
func NewBatchServices() BatchServices {
	return BatchServices{Client: ledger.Client(transparency.PurposeSigningServer, 120*time.Second)}
}

// Presign sends json=… (or xml=…) and certs=….
func (s BatchServices) Presign(ctx context.Context, url string, isJSON bool, batch []byte, chain [][]byte) ([]byte, error) {
	return s.post(ctx, url, batchBody(isJSON, batch, chain))
}

// Postsign adds tridata=….
func (s BatchServices) Postsign(ctx context.Context, url string, isJSON bool, batch []byte, chain [][]byte, triphase []byte) ([]byte, error) {
	return s.post(ctx, url, batchBody(isJSON, batch, chain)+"&tridata="+base64.URLEncoding.EncodeToString(triphase))
}

// Triphase posts a call to the single-signature triphase service.
func (s BatchServices) Triphase(ctx context.Context, url, body string) ([]byte, error) {
	return s.post(ctx, url, body)
}

// batchBody writes the common part of both bodies.
func batchBody(isJSON bool, batch []byte, chain [][]byte) string {
	field := "xml="
	if isJSON {
		field = "json="
	}
	certificates := make([]string, len(chain))
	for index, certificate := range chain {
		certificates[index] = base64.URLEncoding.EncodeToString(certificate)
	}
	return field + base64.URLEncoding.EncodeToString(batch) + "&certs=" + strings.Join(certificates, ";")
}

// post sends a form and returns the body, or the status as ServiceFailure.
func (s BatchServices) post(ctx context.Context, url, body string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, maximumDownload))
	if err != nil {
		return nil, err
	}
	if response.StatusCode/100 != 2 {
		return nil, application.ServiceFailure{Status: response.StatusCode, Body: strings.TrimSpace(string(answer))}
	}
	return answer, nil
}

// KeyRawSigner signs pre-signatures with a key from a file, a card or a store.
type KeyRawSigner struct{}

// Chain returns the key's certificate and the issuers known with it.
func (KeyRawSigner) Chain(key signing.Signer) ([][]byte, error) {
	pair, err := signinfra.LoadKeyPair(key)
	if err != nil {
		return nil, err
	}
	defer pair.Close()
	var chain [][]byte
	for _, certificate := range pair.Certificates() {
		chain = append(chain, certificate.Raw)
	}
	return chain, nil
}

// SignAll hashes each input with the batch's digest and signs it.
func (KeyRawSigner) SignAll(key signing.Signer, inputs [][]byte, digest string) ([][]byte, error) {
	hash, known := digestHash(digest)
	if !known {
		return nil, fmt.Errorf("unknown digest %q", digest)
	}
	pair, err := signinfra.LoadKeyPair(key)
	if err != nil {
		return nil, err
	}
	defer pair.Close()
	signatures := make([][]byte, len(inputs))
	for index, input := range inputs {
		hasher := hash.New()
		hasher.Write(input)
		signature, err := pair.Signer.Sign(rand.Reader, hasher.Sum(nil), hash)
		if err != nil {
			return nil, err
		}
		signatures[index] = signature
	}
	return signatures, nil
}

// digestHash names a digest as AutoFirma does: SHA256 or SHA-256.
func digestHash(name string) (crypto.Hash, bool) {
	hashes := map[string]crypto.Hash{"SHA1": crypto.SHA1, "SHA256": crypto.SHA256, "SHA384": crypto.SHA384, "SHA512": crypto.SHA512,
		"SHA-1": crypto.SHA1, "SHA-256": crypto.SHA256, "SHA-384": crypto.SHA384, "SHA-512": crypto.SHA512}
	hash, known := hashes[strings.ToUpper(name)]
	return hash, known
}

// compile-time checks.
var (
	_ application.BatchServices = BatchServices{}
	_ application.RawSigner     = KeyRawSigner{}
)
