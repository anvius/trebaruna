// Package infrastructure is the only place in trebaruna that builds an HTTP
// client. Every client it hands out records each request in the process
// ledger, so a command can report, and a window can show, every connection the
// program made on the user's behalf (ADR-0010).
package infrastructure

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"codeberg.org/simplicer/trebaruna/src/transparency/domain"
)

// maxEntries bounds the ledger of a long-running server.
const maxEntries = 1000

var ledger struct {
	mu      sync.Mutex
	entries []domain.Connection
}

// original is the standard transport before it was wrapped below; the clients
// this package hands out use it directly so nothing is recorded twice.
var original = http.DefaultTransport

// Libraries that build their own http.Client without a transport — pdfsign
// does, for its timestamp and revocation requests — end up on
// http.DefaultTransport. Wrapping it at start-up means their connections are
// recorded too, marked as coming from a library and classified by what they
// carry.
func init() {
	http.DefaultTransport = recordingTransport{base: original, library: true}
}

// Client returns an HTTP client that records every request under purpose.
func Client(purpose domain.Purpose, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: recordingTransport{purpose: purpose, base: original},
	}
}

// Connections returns a copy of what has been recorded so far.
func Connections() []domain.Connection {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return append([]domain.Connection{}, ledger.entries...)
}

// Reset forgets every recorded connection; tests and per-request servers use it.
func Reset() {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.entries = nil
}

func record(connection domain.Connection) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.entries = append(ledger.entries, connection)
	if overflow := len(ledger.entries) - maxEntries; overflow > 0 {
		ledger.entries = ledger.entries[overflow:]
	}
}

// recordingTransport measures a request and its response and records both
// when the response body is closed, or at once when the request fails.
type recordingTransport struct {
	purpose domain.Purpose
	base    http.RoundTripper
	// library marks the wrapped default transport, whose callers did not say why.
	library bool
}

// userAgent names the program to the servers it calls. Some refuse Go's
// default one (the Estonian trusted list answers 403); a version would only
// help tell users apart.
const userAgent = "trebaruna"

// RoundTrip performs the request and arranges for it to be recorded.
func (t recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Header.Get("User-Agent") == "" {
		request = request.Clone(request.Context())
		request.Header.Set("User-Agent", userAgent)
	}
	purpose, via := t.purpose, ""
	if t.library {
		purpose, via = classify(request), "library"
	}
	connection := domain.Connection{
		Purpose:   purpose,
		Via:       via,
		Method:    request.Method,
		URL:       domain.Redact(request.URL),
		SentBytes: max(request.ContentLength, 0),
		StartedAt: time.Now().UTC(),
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		connection.Error = err.Error()
		connection.DurationMS = time.Since(connection.StartedAt).Milliseconds()
		record(connection)
		return nil, err
	}
	connection.Status = response.StatusCode
	response.Body = &countingBody{ReadCloser: response.Body, connection: connection}
	return response, nil
}

// countingBody counts what the caller reads and records on Close.
type countingBody struct {
	io.ReadCloser
	connection domain.Connection
	once       sync.Once
}

func (b *countingBody) Read(buffer []byte) (int, error) {
	read, err := b.ReadCloser.Read(buffer)
	b.connection.Received += int64(read)
	return read, err
}

// Close records the connection once, with the bytes actually received.
func (b *countingBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		b.connection.DurationMS = time.Since(b.connection.StartedAt).Milliseconds()
		record(b.connection)
	})
	return err
}

// classify names the purpose of a library's request from what it carries:
// the media types of RFC 3161 and RFC 6960, and the conventional CRL suffix.
func classify(request *http.Request) domain.Purpose {
	contentType := strings.ToLower(request.Header.Get("Content-Type"))
	path := strings.ToLower(request.URL.Path)
	switch {
	case strings.Contains(contentType, "timestamp-query"):
		return domain.PurposeTimestamp
	case strings.Contains(contentType, "ocsp-request"), strings.Contains(path, "ocsp"):
		return domain.PurposeRevocation
	case strings.HasSuffix(path, ".crl"):
		return domain.PurposeRevocation
	}
	return domain.PurposeUnattributed
}
