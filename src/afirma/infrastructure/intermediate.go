package infrastructure

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	ledger "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// waitInterval is how often AutoFirma tells the page to keep waiting (C.6).
const waitInterval = 10 * time.Second

// IntermediateServer talks to a site's StorageService and RetrieveService
// (C.2, C.4): it fetches requests the page uploaded, posts "#WAIT" while the
// person decides, and posts the answer, one send at a time so a "#WAIT" never
// overwrites the result.
type IntermediateServer struct {
	// Client makes the requests; production uses the connection record.
	Client *http.Client
	// Interval overrides waitInterval, for tests.
	Interval time.Duration

	mutex     *sync.Mutex
	delivered map[string]bool
}

// NewIntermediateServer builds the client over the connection record.
func NewIntermediateServer() *IntermediateServer {
	return WithClient(ledger.Client(transparency.PurposeWebDelivery, 60*time.Second))
}

// WithClient builds the courier over a given HTTP client.
func WithClient(client *http.Client) *IntermediateServer {
	return &IntermediateServer{Client: client, Interval: waitInterval, mutex: &sync.Mutex{}, delivered: map[string]bool{}}
}

// Deliver posts the answer under the session id.
func (s *IntermediateServer) Deliver(ctx context.Context, channel domain.Channel, answer domain.Answer) error {
	payload, err := encodeAnswer(channel, answer)
	if err != nil {
		return domain.Failure{Code: domain.EncryptingData, Cause: err.Error()}
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.delivered[channel.SessionID] = true
	return s.put(ctx, channel, payload)
}

// Wait posts "#WAIT" now and every interval until stopped or delivered.
func (s *IntermediateServer) Wait(channel domain.Channel) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(s.Interval)
		defer ticker.Stop()
		for {
			s.mutex.Lock()
			if !s.delivered[channel.SessionID] {
				_ = s.put(context.Background(), channel, "#WAIT")
			}
			s.mutex.Unlock()
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// put posts op=put&v=1_0&id=…&dat=… (C.4).
func (s *IntermediateServer) put(ctx context.Context, channel domain.Channel, payload string) error {
	body := "op=put&v=1_0&id=" + url.QueryEscape(channel.SessionID) + "&dat=" + payload
	answer, err := s.post(ctx, channel.StorageURL, body)
	if err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(answer), "err-") {
		return fmt.Errorf("the storage service answered %s", strings.TrimSpace(answer))
	}
	return nil
}

// Fetch retrieves an uploaded request (C.2) and reads it (C.3).
func (s *IntermediateServer) Fetch(ctx context.Context, retrieveURL, fileID, key, cipherParameter string, asJSON bool) (domain.Invocation, error) {
	body, err := s.post(ctx, retrieveURL, "op=get&v=1_0&id="+url.QueryEscape(fileID))
	if err != nil {
		return domain.Invocation{}, domain.Failure{Code: domain.RecoveringData, Cause: err.Error()}
	}
	body = strings.TrimRight(body, "\r\n")
	if len(body) > 8 && strings.HasPrefix(strings.ToLower(body[:8]), "err-") {
		return domain.Invocation{}, domain.Failure{Code: domain.RecoveringData, Cause: body}
	}
	plain, err := openRequest(key, cipherParameter, body)
	if err != nil {
		return domain.Invocation{}, domain.Failure{Code: domain.DecryptingData, Cause: err.Error()}
	}
	if asJSON {
		return domain.ParseRequestJSON(plain, domain.Batch)
	}
	return domain.ParseRequestXML(plain)
}

// post sends a form body and returns the answer text.
func (s *IntermediateServer) post(ctx context.Context, target, body string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "*/*")
	response, err := s.Client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, maximumDownload))
	if err != nil {
		return "", err
	}
	if response.StatusCode/100 != 2 {
		return "", fmt.Errorf("HTTP %d from %s", response.StatusCode, target)
	}
	return string(answer), nil
}

// encodeAnswer writes the answer for the storage servlet (B.1, B.3): failures
// URL-encoded, CANCEL and OK as they are, the rest ciphered element by
// element when the page gave a key, and always URL-safe.
func encodeAnswer(channel domain.Channel, answer domain.Answer) (string, error) {
	switch {
	case answer.Failure:
		return url.QueryEscape(answer.Text()), nil
	case answer.Plain || !channel.Ciphered():
		return answer.Text(), nil
	}
	sealed := make([]string, 0, len(answer.Elements))
	for _, element := range answer.Elements {
		plain, err := base64.URLEncoding.DecodeString(element)
		if err != nil {
			return "", err
		}
		item, err := sealItem(channel, plain)
		if err != nil {
			return "", err
		}
		sealed = append(sealed, item)
	}
	return strings.Join(sealed, "|"), nil
}

// compile-time checks.
var (
	_ application.Courier      = (*IntermediateServer)(nil)
	_ application.RequestStore = (*IntermediateServer)(nil)
)
