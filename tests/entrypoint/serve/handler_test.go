package serve_test

// A protocol handler is reachable by any page the user has open, so the tests
// here are about what it refuses, not about what it does. The design rule: the
// page asks, a person decides, and the page never learns how to decide.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/firma-it/src/entrypoint/serve"
)

// TestURIRequiresTheScheme keeps other schemes out.
func TestURIRequiresTheScheme(t *testing.T) {
	for _, raw := range []string{
		"https://example.org/sign?document=/tmp/a.pdf",
		"autofirma://sign?document=/tmp/a.pdf",
		"firma-it:sign?document=/tmp/a.pdf",
	} {
		if _, _, err := serve.ParseHandlerURI(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}

// TestURIRejectsUnknownParameters: a parameter silently dropped is a parameter
// the caller believes was applied.
func TestURIRejectsUnknownParameters(t *testing.T) {
	_, _, err := serve.ParseHandlerURI("firma-it://sign?document=/tmp/a.pdf&autoapprove=1")
	if err == nil {
		t.Fatal("an unknown parameter was accepted")
	}
	if !strings.Contains(err.Error(), "autoapprove") {
		t.Errorf("the error must name the parameter, got: %v", err)
	}
}

// TestURIRejectsUnknownActions: only signing exists, and guessing is not allowed.
func TestURIRejectsUnknownActions(t *testing.T) {
	if _, _, err := serve.ParseHandlerURI("firma-it://delete?document=/tmp/a.pdf"); err == nil {
		t.Fatal("an unknown action was accepted")
	}
}

// TestURIRequiresADocument covers the empty case.
func TestURIRequiresADocument(t *testing.T) {
	if _, _, err := serve.ParseHandlerURI("firma-it://sign?format=pdf"); err == nil {
		t.Fatal("a request without a document was accepted")
	}
}

// TestURIDecodesPercentEscapes: real paths contain spaces and accents.
func TestURIDecodesPercentEscapes(t *testing.T) {
	_, parameters, err := serve.ParseHandlerURI(
		"firma-it://sign?document=%2Ftmp%2Ffirma%20elettronica.pdf&format=pdf")
	if err != nil {
		t.Fatalf("ParseHandlerURI: %v", err)
	}
	if parameters["document"] != "/tmp/firma elettronica.pdf" {
		t.Errorf("document = %q", parameters["document"])
	}
}

// TestCallbackMustStayInsideTheOrigin is the delivery rule: a signature must not
// be posted to a third party.
func TestCallbackMustStayInsideTheOrigin(t *testing.T) {
	// Same origin: accepted.
	if _, _, err := serve.ParseHandlerURI(
		"firma-it://sign?document=/tmp/a.pdf&origin=https://sede.example.gob.es&" +
			"callback=https://sede.example.gob.es/recibir"); err != nil {
		t.Errorf("a callback inside the origin was refused: %v", err)
	}

	// Different host: refused.
	_, _, err := serve.ParseHandlerURI(
		"firma-it://sign?document=/tmp/a.pdf&origin=https://sede.example.gob.es&" +
			"callback=https://evil.example/collect")
	if err == nil {
		t.Fatal("a callback outside the origin was accepted")
	}

	// No origin declared, callback to a third party: still an absolute URL.
	if _, _, err := serve.ParseHandlerURI(
		"firma-it://sign?document=/tmp/a.pdf&callback=javascript:alert(1)"); err == nil {
		t.Fatal("a non-http callback was accepted")
	}
}

// TestOriginMustBeABareOrigin: an origin with a path is not an origin.
func TestOriginMustBeABareOrigin(t *testing.T) {
	for _, origin := range []string{"https://example.org/path", "example.org", "ftp://example.org"} {
		_, _, err := serve.ParseHandlerURI("firma-it://sign?document=/tmp/a.pdf&origin=" +
			strings.ReplaceAll(origin, ":", "%3A"))
		if err == nil && origin != "ftp://example.org" {
			t.Errorf("origin %q was accepted", origin)
		}
	}
}

// TestDecisionNeedsTheSecret is the central defence: the page cannot approve.
func TestDecisionNeedsTheSecret(t *testing.T) {
	pending := serve.NewPendingRequests()

	request, err := pending.Create(serve.PendingRequest{Path: "/tmp/a.pdf"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if request.Secret == "" {
		t.Fatal("a request must carry a secret for the human to use")
	}

	if err := pending.Decide(request.ID, "wrong-secret", true); err == nil {
		t.Fatal("a request was approved without the secret")
	}
	if err := pending.Decide(request.ID, request.Secret, true); err != nil {
		t.Fatalf("the correct secret was refused: %v", err)
	}
}

// TestSecretNeverLeavesThroughReads: listing or reading must not expose it,
// otherwise the page could read it from the list route and approve itself.
func TestSecretNeverLeavesThroughReads(t *testing.T) {
	pending := serve.NewPendingRequests()

	request, err := pending.Create(serve.PendingRequest{Path: "/tmp/a.pdf"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	read, found := pending.Get(request.ID)
	if !found {
		t.Fatal("the request is not readable")
	}
	if read.Secret != "" {
		t.Error("Get leaked the secret")
	}

	for _, listed := range pending.List() {
		if listed.Secret != "" {
			t.Error("List leaked the secret")
		}
	}
}

// TestApprovalIsSingleUse: replaying the callback must not sign twice.
func TestApprovalIsSingleUse(t *testing.T) {
	pending := serve.NewPendingRequests()

	request, err := pending.Create(serve.PendingRequest{Path: "/tmp/a.pdf"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := pending.Decide(request.ID, request.Secret, true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	if _, err := pending.Take(request.ID); err != nil {
		t.Fatalf("first Take: %v", err)
	}
	if _, err := pending.Take(request.ID); err == nil {
		t.Fatal("a second Take succeeded: the approval was reusable")
	}
}

// TestDecisionCannotBeRepeated: answering twice is answering once, and the second
// answer must not flip the first.
func TestDecisionCannotBeRepeated(t *testing.T) {
	pending := serve.NewPendingRequests()

	request, err := pending.Create(serve.PendingRequest{Path: "/tmp/a.pdf"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := pending.Decide(request.ID, request.Secret, false); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if err := pending.Decide(request.ID, request.Secret, true); err == nil {
		t.Fatal("a decided request accepted a second decision")
	}
	if _, err := pending.Take(request.ID); err == nil {
		t.Fatal("a rejected request was taken")
	}
}

// TestRequestExpires: an unanswered request must not wait forever.
func TestRequestExpires(t *testing.T) {
	pending := serve.NewPendingRequests()

	moment := time.Now()
	pending.Now = func() time.Time { return moment }

	request, err := pending.Create(serve.PendingRequest{Path: "/tmp/a.pdf"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Move past the window.
	moment = moment.Add(serve.ApprovalWindow + time.Second)

	if _, found := pending.Get(request.ID); found {
		t.Error("an expired request is still readable")
	}
	if err := pending.Decide(request.ID, request.Secret, true); err == nil {
		t.Error("an expired request was approved")
	}
}

// TestUnapprovedRequestCannotBeTaken: the default is refusal.
func TestUnapprovedRequestCannotBeTaken(t *testing.T) {
	pending := serve.NewPendingRequests()

	request, err := pending.Create(serve.PendingRequest{Path: "/tmp/a.pdf"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := pending.Take(request.ID); err == nil {
		t.Fatal("an undecided request was taken")
	}
}

// TestIdentifiersAreUnpredictable: a page that could guess an identifier could
// poll someone else's request.
func TestIdentifiersAreUnpredictable(t *testing.T) {
	pending := serve.NewPendingRequests()

	seen := map[string]bool{}
	for index := 0; index < 32; index++ {
		request, err := pending.Create(serve.PendingRequest{Path: "/tmp/a.pdf"})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if len(request.ID) < 32 {
			t.Errorf("identifier %q is too short to be unpredictable", request.ID)
		}
		if seen[request.ID] {
			t.Fatal("an identifier repeated")
		}
		seen[request.ID] = true
	}
}

// TestHiddenFilesAreMostlyDotFree is a small sanity check on the identifier
// alphabet, which must stay URL-safe.
func TestIdentifiersAreURLSafe(t *testing.T) {
	pending := serve.NewPendingRequests()

	request, err := pending.Create(serve.PendingRequest{Path: "/tmp/a.pdf"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, character := range request.ID {
		if !strings.ContainsRune("0123456789abcdef", character) {
			t.Errorf("identifier %q contains %q, which is not URL-safe hex", request.ID, character)
			break
		}
	}
}

// TestRequestRouteRequiresAToken keeps the new routes behind the same guard.
func TestRequestRouteRequiresAToken(t *testing.T) {
	fixture := newFixture(t)

	response, err := http.Post(fixture.server.URL+"/v1/requests", "application/json",
		strings.NewReader(`{"document":"/tmp/a.pdf"}`))
	if err != nil {
		t.Fatalf("POST /v1/requests: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", response.StatusCode)
	}
}

// TestRequestRouteRefusesPathsOutsideTheRoot: the handler is not a bypass.
func TestRequestRouteRefusesPathsOutsideTheRoot(t *testing.T) {
	fixture := newFixture(t)

	response := fixture.call(t, "POST", "/v1/requests",
		map[string]any{"document": "/etc/passwd"}, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.StatusCode)
	}

	var problem map[string]any
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if problem["title"] != "path-rejected" {
		t.Errorf("title = %v", problem["title"])
	}
}

// TestRequestRouteDoesNotReturnTheSecret is the property the whole design rests
// on: the page that creates a request must not learn how to approve it.
func TestRequestRouteDoesNotReturnTheSecret(t *testing.T) {
	fixture := newFixture(t)

	document, _ := fixture.material(t)
	path := fixture.writeFile(t, "signed.xml", document)

	response := fixture.call(t, "POST", "/v1/requests",
		map[string]any{"document": path, "format": "xades"}, nil)

	body := readAllString(t, response)
	if strings.Contains(body, "secret") {
		t.Errorf("the creation response mentions a secret: %s", body)
	}
}

// TestDocumentFromArgument tells a path from a URI, which is what the desktop
// entry hands to the app in the same slot.
func TestDocumentFromArgument(t *testing.T) {
	cases := map[string]string{
		"/home/user/documento.pdf":                           "/home/user/documento.pdf",
		"firma-it://sign?document=%2Fhome%2Fuser%2Fatto.pdf": "/home/user/atto.pdf",
		"firma-it://sign?document=/tmp/a.xml&format=xades":   "/tmp/a.xml",
		"firma-it://unknown?document=/tmp/a.xml":             "",
		"firma-it://sign?autoapprove=1":                      "",
	}

	for argument, want := range cases {
		if got := serve.DocumentFromArgument(argument); got != want {
			t.Errorf("DocumentFromArgument(%q) = %q, want %q", argument, got, want)
		}
	}
}
