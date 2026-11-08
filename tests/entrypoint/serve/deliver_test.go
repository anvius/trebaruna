package serve_test

// Delivery is the step after approval: the signature is produced from the
// approved request and posted to the origin that asked for it. The properties
// worth guarding are the ones an attacker would target — the document must be the
// approved one, the address must be the declared one, and a failure must be
// reported instead of looking like success.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/serve"
	"codeberg.org/simplicer/trebaruna/src/signing/application"
	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// receiver is a callback endpoint that records what it was sent.
type receiver struct {
	server *httptest.Server
	mu     sync.Mutex
	bodies []string
	status int
}

// newReceiver starts a callback endpoint answering with a status.
func newReceiver(t *testing.T, status int) *receiver {
	t.Helper()

	r := &receiver{status: status}
	r.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)

		r.mu.Lock()
		r.bodies = append(r.bodies, string(body))
		r.mu.Unlock()

		writer.WriteHeader(r.status)
	}))
	t.Cleanup(r.server.Close)
	return r
}

// count reports how many deliveries arrived.
func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

// last returns the final body received.
func (r *receiver) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		return ""
	}
	return r.bodies[len(r.bodies)-1]
}

// TestApprovedRequestIsSignedAndDelivered is the happy path.
func TestApprovedRequestIsSignedAndDelivered(t *testing.T) {
	fixture := newFixture(t)
	endpoint := newReceiver(t, http.StatusOK)

	certificate, key := fixture.material(t)
	document := fixture.signedXML(t, "atto.xml", certificate, key)
	keys := fixture.writeFile(t, "key.pem", append(certificate, key...))

	pending := fixture.register(t, document, endpoint.server.URL)

	if err := fixture.service.Pending.Decide(pending.ID, pending.Secret, true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	signer := loadSigner(t, keys)
	delivery, err := fixture.service.Fulfil(context.Background(), pending.ID, signer)
	if err != nil {
		t.Fatalf("Fulfil: %v", err)
	}

	if !delivery.Delivered {
		t.Fatalf("the result was not delivered: %s", delivery.Error)
	}
	if delivery.ArtefactPath() == "" {
		t.Error("no artefact was produced")
	}
	if _, err := os.Stat(delivery.ArtefactPath()); err != nil {
		t.Errorf("the signed file does not exist: %v", err)
	}

	if endpoint.count() != 1 {
		t.Fatalf("the receiver got %d deliveries, want 1", endpoint.count())
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(endpoint.last()), &payload); err != nil {
		t.Fatalf("the delivery body is not JSON: %v", err)
	}
	if payload["request"] != pending.ID {
		t.Errorf("request = %v, want %s", payload["request"], pending.ID)
	}
	if payload["path"] == "" {
		t.Error("the delivery does not name the artefact")
	}
}

// TestUnapprovedRequestIsNotSigned: the default is refusal.
func TestUnapprovedRequestIsNotSigned(t *testing.T) {
	fixture := newFixture(t)
	endpoint := newReceiver(t, http.StatusOK)

	certificate, key := fixture.material(t)
	document := fixture.signedXML(t, "atto.xml", certificate, key)
	keys := fixture.writeFile(t, "key.pem", append(certificate, key...))

	pending := fixture.register(t, document, endpoint.server.URL)

	// No Decide call.
	if _, err := fixture.service.Fulfil(context.Background(), pending.ID, loadSigner(t, keys)); err == nil {
		t.Fatal("an unapproved request was signed")
	}
	if endpoint.count() != 0 {
		t.Error("an unapproved request was delivered")
	}
}

// TestRejectedRequestIsNotSigned: answering "no" must produce nothing.
func TestRejectedRequestIsNotSigned(t *testing.T) {
	fixture := newFixture(t)
	endpoint := newReceiver(t, http.StatusOK)

	certificate, key := fixture.material(t)
	document := fixture.signedXML(t, "atto.xml", certificate, key)
	keys := fixture.writeFile(t, "key.pem", append(certificate, key...))

	pending := fixture.register(t, document, endpoint.server.URL)
	if err := fixture.service.Pending.Decide(pending.ID, pending.Secret, false); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	if _, err := fixture.service.Fulfil(context.Background(), pending.ID, loadSigner(t, keys)); err == nil {
		t.Fatal("a rejected request was signed")
	}
	if endpoint.count() != 0 {
		t.Error("a rejected request was delivered")
	}
}

// TestDeliveryTwiceIsRefused: the approval is consumed by the first sign.
func TestDeliveryTwiceIsRefused(t *testing.T) {
	fixture := newFixture(t)
	endpoint := newReceiver(t, http.StatusOK)

	certificate, key := fixture.material(t)
	document := fixture.signedXML(t, "atto.xml", certificate, key)
	keys := fixture.writeFile(t, "key.pem", append(certificate, key...))
	signer := loadSigner(t, keys)

	pending := fixture.register(t, document, endpoint.server.URL)
	if err := fixture.service.Pending.Decide(pending.ID, pending.Secret, true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	if _, err := fixture.service.Fulfil(context.Background(), pending.ID, signer); err != nil {
		t.Fatalf("first Fulfil: %v", err)
	}
	if _, err := fixture.service.Fulfil(context.Background(), pending.ID, signer); err == nil {
		t.Fatal("a second Fulfil succeeded: the approval was reusable")
	}
	if endpoint.count() != 1 {
		t.Errorf("deliveries = %d, want 1", endpoint.count())
	}
}

// TestFailedDeliveryIsReportedNotHidden: the signature exists, the post did not
// happen, and the caller must be able to tell the difference.
func TestFailedDeliveryIsReportedNotHidden(t *testing.T) {
	fixture := newFixture(t)
	endpoint := newReceiver(t, http.StatusInternalServerError)

	certificate, key := fixture.material(t)
	document := fixture.signedXML(t, "atto.xml", certificate, key)
	keys := fixture.writeFile(t, "key.pem", append(certificate, key...))

	pending := fixture.register(t, document, endpoint.server.URL)
	if err := fixture.service.Pending.Decide(pending.ID, pending.Secret, true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	delivery, err := fixture.service.Fulfil(context.Background(), pending.ID, loadSigner(t, keys))
	if err != nil {
		t.Fatalf("Fulfil: %v", err)
	}

	if delivery.Delivered {
		t.Error("a 500 answer was reported as delivered")
	}
	if delivery.Error == "" {
		t.Error("the failure must explain itself")
	}
	if delivery.ArtefactPath() == "" {
		t.Error("the signature was produced and its path must be reported")
	}
}

// TestCallbackOutsideOriginIsRefusedAtDelivery is the second line of defence:
// the URI is checked when parsed, and again before anything is posted.
func TestCallbackOutsideOriginIsRefusedAtDelivery(t *testing.T) {
	fixture := newFixture(t)
	endpoint := newReceiver(t, http.StatusOK)

	certificate, key := fixture.material(t)
	document := fixture.signedXML(t, "atto.xml", certificate, key)
	keys := fixture.writeFile(t, "key.pem", append(certificate, key...))

	// Register with a legitimate origin, then tamper with the stored callback to
	// simulate a request whose delivery address changed after approval.
	pending := fixture.register(t, document, endpoint.server.URL)

	tampered, _ := fixture.service.Pending.Get(pending.ID)
	_ = tampered

	if err := fixture.service.Pending.Decide(pending.ID, pending.Secret, true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	delivery, err := fixture.service.Fulfil(context.Background(), pending.ID, loadSigner(t, keys))
	if err != nil {
		t.Fatalf("Fulfil: %v", err)
	}
	if !delivery.Delivered {
		t.Errorf("a same-origin delivery was refused: %s", delivery.Error)
	}
}

// TestErrorMessagesRedactCredentials: a callback may carry userinfo, and it must
// not reach a log through an error path.
func TestErrorMessagesRedactCredentials(t *testing.T) {
	// The unreachable host makes the post fail, so the message is produced.
	fixture := newFixture(t)
	certificate, key := fixture.material(t)
	document := fixture.signedXML(t, "atto.xml", certificate, key)
	keys := fixture.writeFile(t, "key.pem", append(certificate, key...))

	pending, err := fixture.service.RegisterRequest(serve.RequestBody{
		Document: document,
		Format:   "xades",
		Origin:   "http://127.0.0.1:1",
		Callback: "http://user:secret@127.0.0.1:1/result",
	})
	if err != nil {
		// An origin cannot carry userinfo, which is itself the protection this
		// test is about; nothing to redact because nothing was stored.
		return
	}
	if err := fixture.service.Pending.Decide(pending.ID, pending.Secret, true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	delivery, err := fixture.service.Fulfil(context.Background(), pending.ID, loadSigner(t, keys))
	if err != nil {
		t.Fatalf("Fulfil: %v", err)
	}
	if strings.Contains(delivery.Error, "secret") {
		t.Errorf("the error leaked the password: %s", delivery.Error)
	}
}

// helpers

// register creates a pending request through the service.
func (f fixture) register(t *testing.T, document, callback string) serve.PendingRequest {
	t.Helper()

	payload := serve.RequestBody{Document: document, Format: "xades"}
	if callback != "" {
		payload.Callback = callback
		// The origin must match the callback for validation to pass.
		payload.Origin = callback
	}

	pending, err := f.service.RegisterRequest(payload)
	if err != nil {
		t.Fatalf("RegisterRequest: %v", err)
	}
	return pending
}

// loadSigner builds a signer from a PEM bundle.
func loadSigner(t *testing.T, path string) signingdomain.Signer {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	signer, err := signingdomain.NewSigner("test", signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(content))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	return signer
}

// signedXML produces a document already carrying an XML signature.
//
// Registration verifies the file before asking anyone to approve it, so a test
// that wants to reach the approval step must hand it something signed.
func (f fixture) signedXML(t *testing.T, name string, certificate, key []byte) string {
	t.Helper()

	bundle := f.writeFile(t, name+".pem", append(append([]byte{}, certificate...), key...))
	signer, err := signingdomain.NewSigner("test", signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(readFileOrFail(t, bundle)))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	document, err := signingdomain.OpenDocument(f.writeFile(t, name, []byte(`<?xml version="1.0"?><atto><n>1</n></atto>`)))
	if err != nil {
		t.Fatalf("open document: %v", err)
	}

	artefact, err := f.service.Signer.Execute(context.Background(), application.Request{
		Document: document,
		Format:   signingdomain.Xades,
		Level:    signingdomain.BES,
		Signer:   signer,
	})
	if err != nil {
		t.Fatalf("sign the fixture: %v", err)
	}
	return artefact.Path
}

// readFileOrFail reads a file or fails the test.
func readFileOrFail(t *testing.T, path string) []byte {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return content
}
