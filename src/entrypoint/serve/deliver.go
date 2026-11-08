package serve

// Delivery: what happens after a person approves a request.
//
// The approval is the authorisation; this file is the execution. It signs the
// document the request named and delivers the result to the origin the request
// declared, so the page that asked can pick it up without ever holding the
// approval secret.
//
// Two rules shape it:
//
//   - the signature is produced from the *approved* request only, never from
//     anything the caller sends later, so what the person saw is what gets signed;
//   - delivery is a POST to the declared callback and nowhere else. A signature
//     sent to an address the caller can influence after approval is a signature
//     handed to whoever asks last.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	signingdomain "codeberg.org/simplicer/firma-it/src/signing/domain"
)

// DeliveryTimeout bounds the post back to the caller.
//
// A page that hangs must not hold a signed document in memory indefinitely.
const DeliveryTimeout = 20 * time.Second

// Delivery is what was sent back, and what came of it.
type Delivery struct {
	// Delivered reports a successful post.
	Delivered bool
	// Callback is the address used.
	Callback string
	// StatusCode is the responder's HTTP status.
	StatusCode int
	// Error explains a failure in English.
	Error string
	// Artefact is the file that was produced, whether or not it was delivered.
	Artefact application.Artefact
}

// ArtefactPath is where the signed document was written.
func (d Delivery) ArtefactPath() string { return d.Artefact.Path }

// Fulfil signs an approved request and delivers it.
//
// It is the only path from an approval to a signature, and it reads the document
// from the request rather than from a parameter, so a caller cannot swap the
// document between approval and signing.
func (s *Service) Fulfil(ctx context.Context, identifier string, keySource signingdomain.Signer) (Delivery, error) {
	pending, err := s.Pending.Take(identifier)
	if err != nil {
		return Delivery{}, err
	}

	document, err := signingdomain.OpenDocument(pending.Path)
	if err != nil {
		return Delivery{}, fmt.Errorf("open the approved document: %w", err)
	}

	format, err := signingdomain.ParseFormat(pending.Format)
	if err != nil {
		return Delivery{}, fmt.Errorf("the approved request carries an unusable format: %w", err)
	}
	level, err := signingdomain.ParseLevel("bes")
	if err != nil {
		return Delivery{}, err
	}

	artefact, err := s.Signer.Execute(ctx, application.Request{
		Document: document,
		Format:   format,
		Level:    level,
		Signer:   keySource,
	})
	if err != nil {
		return Delivery{}, fmt.Errorf("sign the approved document: %w", err)
	}

	delivery := Delivery{Callback: pending.Screen.Callback, Artefact: artefact}
	if pending.Screen.Callback == "" {
		// No callback: the signature stays on disk and the caller is told where.
		return delivery, nil
	}

	if err := s.post(ctx, pending, artefact); err != nil {
		delivery.Error = err.Error()
		return delivery, nil
	}
	delivery.Delivered = true
	return delivery, nil
}

// post sends the signature to the declared callback.
//
// The body carries the artefact path and the verification verdict, not the file
// itself: a page that just received a signature can read it from the local API,
// and shipping a few megabytes through a form post serves nobody.
func (s *Service) post(ctx context.Context, pending PendingRequest, artefact application.Artefact) error {
	if err := validateCallback(pending.Screen.Callback, pending.Screen.Origin); err != nil {
		return err
	}

	payload := map[string]any{
		"request":     pending.ID,
		"path":        artefact.Path,
		"format":      string(artefact.Format),
		"level":       string(artefact.Level),
		"size":        artefact.Size,
		"signed_at":   artefact.SignedAt.UTC().Format(time.RFC3339),
		"signer":      artefact.SignerName,
		"verdict":     string(pending.Report.Verdict()),
		"self_signed": artefact.SelfSigned,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode the result: %w", err)
	}

	timeout := DeliveryTimeout
	if s.Now != nil {
		_ = timeout
	}

	sendContext, cancel := context.WithTimeout(ctx, DeliveryTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(sendContext, http.MethodPost, pending.Screen.Callback, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build the delivery: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	// The origin is declared, not implied: a receiver can check that the delivery
	// came from the request it made.
	request.Header.Set("X-Firma-Request", pending.ID)
	if pending.Screen.Origin != "" {
		request.Header.Set("Origin", pending.Screen.Origin)
	}

	client := s.deliveryClient()
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("deliver to %s: %w", redactURL(pending.Screen.Callback), err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return fmt.Errorf("the receiver answered %s: %s",
			response.Status, truncateText(string(detail), 200))
	}
	return nil
}

// deliveryClient returns the HTTP client for delivery, bounded in time.
func (s *Service) deliveryClient() *http.Client {
	if s.Sender != nil {
		return s.Sender
	}
	return &http.Client{Timeout: DeliveryTimeout}
}

// redactURL keeps credentials out of error messages.
//
// A callback carrying userinfo would otherwise end up in a log, which is how
// secrets leak from error paths.
func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "<unparseable url>"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// truncateText shortens a message for a report.
func truncateText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}
