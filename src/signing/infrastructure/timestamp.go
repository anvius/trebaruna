package infrastructure

import (
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"time"
)

// oidSignatureTimeStampToken is the CMS unsigned attribute that carries an
// RFC 3161 token, turning a BES signature into a B-T one (EN 319 122-1 §6.2).
var oidSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// Timestamper requests RFC 3161 timestamp responses.
//
// It deliberately does nothing else: attaching the token to a CMS structure is
// the cms package's job, because only that package knows the byte layout of the
// unsigned attributes.
type Timestamper interface {
	// Token requests a timestamp over a digest the caller already computed.
	// Passing content here instead of its digest is what produced tokens whose
	// imprint no other implementation could reproduce.
	Token(ctx context.Context, digest []byte, url, username, secret string) ([]byte, error)
}

// Rfc3161Timestamper talks to any qualified timestamp authority.
type Rfc3161Timestamper struct {
	client *http.Client
}

// NewRfc3161Timestamper builds the client. A bounded timeout matters: a hung
// TSA must not hang the signature.
func NewRfc3161Timestamper() *Rfc3161Timestamper {
	return &Rfc3161Timestamper{client: &http.Client{Timeout: 45 * time.Second}}
}

// Token performs the request/response exchange defined by RFC 3161.
func (t *Rfc3161Timestamper) Token(ctx context.Context, digest []byte, url, username, secret string) ([]byte, error) {
	request, err := BuildTimestampRequest(digest, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(request))
	if err != nil {
		return nil, fmt.Errorf("build TSA request to %s: %w", url, err)
	}
	httpRequest.Header.Set("Content-Type", "application/timestamp-query")
	if username != "" {
		httpRequest.SetBasicAuth(username, secret)
	}

	response, err := t.client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("contact TSA %s: %w", url, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read TSA response: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"TSA %s answered %d: %s\n"+
				"  401 usually means the authority needs credentials; many public ones do.\n"+
				"  list free qualified authorities with: trebaruna tsa list --territory IT",
			url, response.StatusCode, truncate(string(body), 200),
		)
	}

	return body, nil
}

// truncate keeps error messages readable.
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// compile-time check.
var _ Timestamper = (*Rfc3161Timestamper)(nil)
