package infrastructure

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"codeberg.org/anvius/pignus/src/verification/domain"
	"golang.org/x/crypto/ocsp"
)

// OCSPChecker asks a responder whether a certificate is revoked.
//
// The request is built for one certificate against its issuer, with the issuer's
// name key hash and public key hash both filled in. Go's ocsp package accepts a
// responder that answers only one of them, and some authorities do exactly that.
//
// This is the only part of verification that reaches the network. It is never
// called unless the caller asked for it: a verification that silently contacts a
// third party is a verification that leaks which documents you open.
type OCSPChecker struct {
	// Client is the HTTP client. Nil uses a bounded default.
	Client *http.Client
	// Timeout bounds one query. Zero uses 10 seconds.
	Timeout time.Duration
	// Now is the clock, injected for tests.
	Now time.Time
	// MaxBody bounds the response we are willing to read.
	MaxBody int64
}

// NewOCSPChecker builds the checker with a bounded client.
func NewOCSPChecker() *OCSPChecker {
	return &OCSPChecker{
		Client:  &http.Client{},
		Timeout: 10 * time.Second,
		Now:     time.Now(),
		MaxBody: 256 * 1024,
	}
}

// Check queries every OCSP endpoint the certificate publishes until one answers.
//
// A definitive answer wins immediately. A transport failure is not an answer, so
// the next responder is tried; if none answers, the result is Unknown and says
// so. It must never be reported as "not revoked".
func (c *OCSPChecker) Check(ctx context.Context, certificate, issuer *x509.Certificate) domain.Revocation {
	now := c.Now
	if now.IsZero() {
		now = time.Now()
	}

	if certificate == nil {
		return domain.Revocation{
			Status:    domain.RevocationUnknown,
			Reason:    "no certificate to check",
			CheckedAt: now,
		}
	}
	if issuer == nil {
		return domain.Revocation{
			Status:    domain.RevocationUnknown,
			Reason:    "the issuer certificate is unavailable, so an OCSP request cannot be built",
			CheckedAt: now,
		}
	}

	urls := certificate.OCSPServer
	if len(urls) == 0 {
		return domain.Revocation{
			Status:    domain.RevocationUnsupported,
			Reason:    "the certificate publishes no OCSP responder",
			CheckedAt: now,
		}
	}

	requestDER, err := ocsp.CreateRequest(certificate, issuer, &ocsp.RequestOptions{Hash: 0})
	if err != nil {
		return domain.Revocation{
			Status:    domain.RevocationUnknown,
			Reason:    fmt.Sprintf("cannot build the OCSP request: %v", err),
			CheckedAt: now,
		}
	}

	var lastErr error
	for _, url := range urls {
		response, err := c.query(ctx, url, requestDER)
		if err != nil {
			lastErr = err
			continue
		}

		parsed, err := ocsp.ParseResponseForCert(response, certificate, issuer)
		if err != nil {
			lastErr = fmt.Errorf("parse the response from %s: %w", url, err)
			continue
		}

		if err := c.checkFreshness(parsed, now); err != nil {
			lastErr = fmt.Errorf("%s: %w", url, err)
			continue
		}

		verdict := c.verdict(parsed, now)
		// Keep the answer as it arrived: a /DSS must embed the responder's own
		// bytes, not a re-encoding, or its signature stops matching.
		verdict.RawResponse = response
		return verdict
	}

	return domain.Revocation{
		Status:    domain.RevocationUnknown,
		Reason:    fmt.Sprintf("no OCSP responder answered: %v", lastErr),
		CheckedAt: now,
	}
}

// query posts one OCSP request and returns the raw response.
func (c *OCSPChecker) query(ctx context.Context, url string, requestDER []byte) ([]byte, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// RFC 6960 §4.1.1: the request travels in the body, not in a GET. Base64 GET
	// is a historical extension and some responders ignore it.
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestDER))
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}
	httpRequest.Header.Set("Content-Type", "application/ocsp-request")
	httpRequest.Header.Set("Accept", "application/ocsp-response")

	client := c.Client
	if client == nil {
		client = &http.Client{}
	}

	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("contact %s: %w", url, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", url, response.Status)
	}

	limit := c.MaxBody
	if limit <= 0 {
		limit = 256 * 1024
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("read the response from %s: %w", url, err)
	}
	return body, nil
}

// checkFreshness rejects a response outside the window it claims.
//
// An outdated answer is worse than none: it says "not revoked" about a moment
// that has passed.
func (c *OCSPChecker) checkFreshness(response *ocsp.Response, now time.Time) error {
	// ThisUpdate bounds the past; NextUpdate bounds the future. A responder that
	// omits NextUpdate is leaving the answer open-ended, which OCSP permits.
	if !response.NextUpdate.IsZero() && now.After(response.NextUpdate.Add(24*time.Hour)) {
		return fmt.Errorf("the response expired on %s", response.NextUpdate.UTC().Format(time.RFC3339))
	}
	if !response.ThisUpdate.IsZero() && now.Add(24*time.Hour).Before(response.ThisUpdate) {
		return fmt.Errorf("the response is dated %s, in the future", response.ThisUpdate.UTC().Format(time.RFC3339))
	}
	return nil
}

// verdict maps an OCSP answer onto the domain.
func (c *OCSPChecker) verdict(response *ocsp.Response, now time.Time) domain.Revocation {
	switch response.Status {
	case ocsp.Good:
		return domain.Revocation{
			Status:    domain.RevocationGood,
			Source:    "ocsp",
			CheckedAt: now,
		}
	case ocsp.Revoked:
		return domain.Revocation{
			Status:    domain.RevocationRevoked,
			RevokedAt: response.RevokedAt,
			Source:    "ocsp",
			Reason:    "the responder reports the certificate as revoked",
			CheckedAt: now,
		}
	default:
		// Unknown status, or one this tool does not understand. Not an answer.
		return domain.Revocation{
			Status:    domain.RevocationUnknown,
			Source:    "ocsp",
			Reason:    "the responder does not know this certificate",
			CheckedAt: now,
		}
	}
}
