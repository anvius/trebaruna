// Package domain describes what the program tells the user about its own
// network activity: every connection, why it was made, and what it moved.
package domain

import (
	"net/url"
	"time"
)

// Purpose names why a connection was opened. A connection without a purpose
// cannot be made: the HTTP client is only handed out with one (ADR-0010).
type Purpose string

const (
	// PurposeTimestamp asks a timestamp authority to date a signature.
	PurposeTimestamp Purpose = "timestamp"

	// PurposeRevocation asks an OCSP responder whether a certificate was revoked.
	PurposeRevocation Purpose = "revocation"

	// PurposeTrustList downloads the EU list of lists or a national list.
	PurposeTrustList Purpose = "trust-list"

	// PurposeWebDelivery hands a signed document back to the page that asked.
	PurposeWebDelivery Purpose = "web-delivery"

	// PurposeLocalAPI talks to trebaruna's own server on this machine.
	PurposeLocalAPI Purpose = "local-api"

	// PurposeSigningServer talks to the site that requested a signature through
	// the AutoFirma protocol (intermediate and three-phase servers).
	PurposeSigningServer Purpose = "signing-server"

	// PurposeRemoteSigning asks a remote signing provider to sign a hash.
	PurposeRemoteSigning Purpose = "remote-signing"

	// PurposeUpdateCheck asks where trebaruna is published for its newest
	// release, when the person asks.
	PurposeUpdateCheck Purpose = "update-check"

	// PurposeDirectory looks a recipient's certificate up in an LDAP
	// directory, to encrypt for them.
	PurposeDirectory Purpose = "directory"

	// PurposeUnattributed is a connection a library opened that the program
	// could not classify. It is still recorded; a test keeps our own flows from
	// producing one.
	PurposeUnattributed Purpose = "unattributed"
)

// Connection is one request the program made.
type Connection struct {
	Purpose Purpose `json:"purpose"`
	Method  string  `json:"method"`
	// URL is the destination without credentials or query values, which may
	// carry secrets or personal data.
	URL        string    `json:"url"`
	Status     int       `json:"status,omitempty"`
	SentBytes  int64     `json:"sent_bytes"`
	Received   int64     `json:"received_bytes"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
	// Via is "library" when a third-party package opened the connection with
	// its own client; empty when trebaruna's recording client did.
	Via string `json:"via,omitempty"`
}

// Host is the destination's host, for short listings.
func (c Connection) Host() string {
	parsed, err := url.Parse(c.URL)
	if err != nil {
		return c.URL
	}
	return parsed.Host
}

// Redact keeps scheme, host and path. User information is dropped and query
// values are replaced, so the record shows where a request went without
// repeating what it carried.
func Redact(raw *url.URL) string {
	if raw == nil {
		return ""
	}
	clean := url.URL{Scheme: raw.Scheme, Host: raw.Host, Path: raw.Path}
	if raw.RawQuery != "" {
		values := raw.Query()
		redacted := url.Values{}
		for key := range values {
			redacted.Set(key, "…")
		}
		clean.RawQuery = redacted.Encode()
	}
	return clean.String()
}
