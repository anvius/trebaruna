package serve

// Protocol handler support: the half a web page talks to.
//
// A web page cannot spawn a process, so it asks the operating system to open a
// custom URI, and the desktop app receives it. Implementing only that much is
// what made previous local signing agents exploitable: any page the user had open
// could ask for a signature, and the agent would produce one.
//
// This file therefore implements the request half only, and it cannot sign on its
// own. A request:
//
//   1. must resolve to a document inside the allowed roots;
//   2. is verified immediately, so the user is never asked about a file whose
//      content nobody has looked at;
//   3. waits for an explicit approval, keyed by a secret the page never sees;
//   4. expires in a short window;
//   5. is single use.
//
// The secret is the point. Whoever triggered the URI has no way to read it, so a
// drive-by request cannot be approved by anyone except the person sitting at the
// machine, and that person is shown the signer and the verdict before deciding.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	verification "codeberg.org/anvius/pignus/src/verification/domain"
)

// HandlerScheme is the URI scheme the desktop app registers.
//
// It is deliberately not the scheme used by any other product: two applications
// claiming the same scheme means the operating system picks one and the other
// silently never runs.
const HandlerScheme = "pignus"

// ApprovalWindow is how long a request waits for a decision.
//
// Thirty seconds is enough to read what is being signed and not enough to leave a
// request sitting around for a page to try again later.
const ApprovalWindow = 30 * time.Second

// Screen is the answer to "where is the page that will receive the result".
//
// Only the origin is kept: the path and query of a callback can carry a session
// token belonging to the caller, and this tool has no reason to store it.
type Screen struct {
	// Origin is the scheme and host, e.g. "https://sede.example.gob.es".
	Origin string
	// Callback is where the result is posted, when the request supplies one.
	Callback string
}

// PendingRequest is a signature the user has been asked about.
type PendingRequest struct {
	// ID identifies the request in the URL and in the UI.
	ID string
	// Path is the resolved document.
	Path string
	// Format and Territory are what the caller asked for.
	Format    string
	Territory string
	// Screen is where the result would be delivered.
	Screen Screen
	// Report is what was found in the file, so the decision is informed.
	Report verification.DocumentReport
	// CreatedAt and ExpiresAt bound the window.
	CreatedAt time.Time
	ExpiresAt time.Time
	// Secret must be presented to approve or reject. It is shown only in the
	// desktop app, never returned over the request that created it.
	Secret string
	// decided is set once the user answers, so a replayed approval does nothing.
	decided bool
	// approved records the answer.
	approved bool
}

// PendingRequests holds the requests awaiting a decision.
//
// It is in memory on purpose: a request that outlives the process is a request
// nobody is looking at, and persisting a signing intent is a liability with no
// benefit.
type PendingRequests struct {
	mu       sync.Mutex
	requests map[string]*PendingRequest
	// Now is the clock, injected for tests.
	Now func() time.Time
}

// NewPendingRequests builds the store.
func NewPendingRequests() *PendingRequests {
	return &PendingRequests{requests: map[string]*PendingRequest{}, Now: time.Now}
}

// Create records a request and returns it.
//
// The identifier and the secret are generated here, not taken from the caller: a
// page that could choose either could guess someone else's.
func (p *PendingRequests) Create(request PendingRequest) (PendingRequest, error) {
	identifier, err := randomHex(16)
	if err != nil {
		return PendingRequest{}, err
	}
	secret, err := randomHex(32)
	if err != nil {
		return PendingRequest{}, err
	}

	now := p.now()
	request.ID = identifier
	request.Secret = secret
	request.CreatedAt = now
	request.ExpiresAt = now.Add(ApprovalWindow)
	request.decided = false
	request.approved = false

	p.mu.Lock()
	defer p.mu.Unlock()

	// Sweep on write: an expired entry is not a request any more, and keeping it
	// would let a page retry an old identifier.
	for key, existing := range p.requests {
		if now.After(existing.ExpiresAt) {
			delete(p.requests, key)
		}
	}

	stored := request
	p.requests[identifier] = &stored
	return request, nil
}

// Decide records the user's answer.
//
// The secret is compared in constant time, and a request can only be decided
// once: approving twice would sign twice.
func (p *PendingRequests) Decide(identifier, secret string, approved bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	request, found := p.requests[identifier]
	if !found {
		return fmt.Errorf("no signature request with that identifier")
	}
	if p.now().After(request.ExpiresAt) {
		delete(p.requests, identifier)
		return fmt.Errorf("the request expired before it was approved")
	}
	if request.decided {
		return fmt.Errorf("the request was already answered")
	}
	if !constantTimeEqual(secret, request.Secret) {
		return fmt.Errorf("the approval secret does not match")
	}

	request.decided = true
	request.approved = approved
	return nil
}

// Take returns an approved request and removes it.
//
// Removal on read is what makes the approval single use: a page cannot replay the
// callback to obtain a second signature.
func (p *PendingRequests) Take(identifier string) (PendingRequest, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	request, found := p.requests[identifier]
	if !found {
		return PendingRequest{}, fmt.Errorf("no signature request with that identifier")
	}
	delete(p.requests, identifier)

	if !request.decided {
		return PendingRequest{}, fmt.Errorf("the request has not been approved")
	}
	if !request.approved {
		return PendingRequest{}, fmt.Errorf("the request was rejected")
	}
	if p.now().After(request.ExpiresAt) {
		return PendingRequest{}, fmt.Errorf("the request expired before it was used")
	}
	return *request, nil
}

// Get returns a copy without removing it, for rendering.
func (p *PendingRequests) Get(identifier string) (PendingRequest, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	request, found := p.requests[identifier]
	if !found || p.now().After(request.ExpiresAt) {
		return PendingRequest{}, false
	}
	// The secret never leaves the store through this path.
	copied := *request
	copied.Secret = ""
	return copied, true
}

// List returns the pending requests for display.
func (p *PendingRequests) List() []PendingRequest {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	list := make([]PendingRequest, 0, len(p.requests))
	for _, request := range p.requests {
		if now.After(request.ExpiresAt) {
			continue
		}
		copied := *request
		copied.Secret = ""
		list = append(list, copied)
	}
	return list
}

// now reads the clock, tolerating a zero value.
func (p *PendingRequests) now() time.Time {
	if p.Now == nil {
		return time.Now()
	}
	return p.Now()
}

// ParseHandlerURI reads a pignus:// URI into a request.
//
// The shape is deliberately explicit rather than a positional blob, because these
// URIs arrive from untrusted pages:
//
//	pignus://sign?document=<path>&format=<pdf|cades|xades>&territory=<ISO>&origin=<url>&callback=<url>
//
// Anything not understood is refused instead of ignored: a parameter silently
// dropped is a parameter the user thinks was applied.
func ParseHandlerURI(raw string) (Screen, map[string]string, error) {
	const prefix = HandlerScheme + "://"

	if !strings.HasPrefix(raw, prefix) {
		return Screen{}, nil, fmt.Errorf("not a %s:// URI", HandlerScheme)
	}

	rest := raw[len(prefix):]
	action, query, hasQuery := strings.Cut(rest, "?")
	if strings.TrimSpace(strings.ToLower(action)) != "sign" {
		return Screen{}, nil, fmt.Errorf("unsupported action %q: only \"sign\" exists", action)
	}
	if !hasQuery {
		return Screen{}, nil, fmt.Errorf("the request carries no parameters")
	}

	parameters := map[string]string{}
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		name, value, hasValue := strings.Cut(pair, "=")
		if !hasValue {
			return Screen{}, nil, fmt.Errorf("parameter %q has no value", name)
		}
		decoded, err := decodeQueryValue(value)
		if err != nil {
			return Screen{}, nil, fmt.Errorf("parameter %q is not valid percent-encoding", name)
		}

		switch name {
		case "document", "format", "territory", "origin", "callback":
			parameters[name] = decoded
		default:
			// An unknown parameter is refused: silently dropping it would let a
			// page believe it configured something it did not.
			return Screen{}, nil, fmt.Errorf("unknown parameter %q", name)
		}
	}

	if parameters["document"] == "" {
		return Screen{}, nil, fmt.Errorf("the request names no document")
	}

	screen := Screen{Origin: parameters["origin"], Callback: parameters["callback"]}
	if screen.Origin != "" {
		if err := validateOrigin(screen.Origin); err != nil {
			return Screen{}, nil, err
		}
	}
	if screen.Callback != "" {
		if err := validateCallback(screen.Callback, screen.Origin); err != nil {
			return Screen{}, nil, err
		}
	}

	return screen, parameters, nil
}

// validateOrigin accepts only an absolute http(s) origin with no path.
func validateOrigin(origin string) error {
	scheme, rest, found := strings.Cut(origin, "://")
	if !found {
		return fmt.Errorf("origin %q is not absolute", origin)
	}
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("origin %q must use http or https", origin)
	}
	if rest == "" || strings.ContainsAny(rest, "/?#") {
		return fmt.Errorf("origin %q must contain only scheme and host", origin)
	}
	return nil
}

// validateCallback keeps the result delivery inside the origin the caller declared.
//
// A callback pointing anywhere else would turn the handler into a way to post a
// signature to a third party.
func validateCallback(callback, origin string) error {
	scheme, _, found := strings.Cut(callback, "://")
	if !found || (scheme != "https" && scheme != "http") {
		return fmt.Errorf("callback %q must be an absolute http(s) URL", callback)
	}
	if origin != "" && !strings.HasPrefix(callback, origin+"/") && callback != origin {
		return fmt.Errorf("callback %q is outside the declared origin", callback)
	}
	return nil
}

// decodeQueryValue decodes percent escapes and '+' as space.
func decodeQueryValue(value string) (string, error) {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '+':
			builder.WriteByte(' ')
		case '%':
			if index+2 >= len(value) {
				return "", fmt.Errorf("truncated escape")
			}
			high, err := hexValue(value[index+1])
			if err != nil {
				return "", err
			}
			low, err := hexValue(value[index+2])
			if err != nil {
				return "", err
			}
			builder.WriteByte(byte(high<<4 | low))
			index += 2
		default:
			builder.WriteByte(value[index])
		}
	}
	return builder.String(), nil
}

// hexValue converts one hexadecimal digit.
func hexValue(character byte) (int, error) {
	switch {
	case character >= '0' && character <= '9':
		return int(character - '0'), nil
	case character >= 'a' && character <= 'f':
		return int(character-'a') + 10, nil
	case character >= 'A' && character <= 'F':
		return int(character-'A') + 10, nil
	}
	return 0, fmt.Errorf("%q is not a hexadecimal digit", character)
}

// randomHex returns n random bytes as hex.
func randomHex(n int) (string, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate a random value: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

// constantTimeEqual compares two secrets without leaking their length prefix.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for index := 0; index < len(a); index++ {
		difference |= a[index] ^ b[index]
	}
	return difference == 0
}
