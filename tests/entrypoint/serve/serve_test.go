package serve_test

// The local HTTP API is a known attack surface: local signing agents have been
// made exploitable by any page the user happened to open. The tests below are
// therefore weighted towards the defences, not the features: a server that signs
// correctly but accepts a cross-origin request is worse than no server at all.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/anvius/pignus/src/entrypoint/serve"
	"codeberg.org/anvius/pignus/src/signing/application"
	signingdomain "codeberg.org/anvius/pignus/src/signing/domain"
	"codeberg.org/anvius/pignus/src/signing/infrastructure"
	verificationapp "codeberg.org/anvius/pignus/src/verification/application"
	verification "codeberg.org/anvius/pignus/src/verification/domain"
	verificationinfra "codeberg.org/anvius/pignus/src/verification/infrastructure"
)

// fixture is a running service with a token and an allowed directory.
type fixture struct {
	service *serve.Service
	server  *httptest.Server
	token   string
	root    string
}

// newFixture builds the service over real adapters.
func newFixture(t *testing.T) fixture {
	t.Helper()

	root := t.TempDir()
	timestamper := infrastructure.NewRfc3161Timestamper()

	service := &serve.Service{
		Signer: application.NewSignDocument(
			infrastructure.DiskStore{},
			application.SystemClock{},
			infrastructure.CertificateInspector{},
			infrastructure.NewCadesSigner(timestamper),
			infrastructure.NewPadesSigner(timestamper),
			infrastructure.NewXadesSigner(timestamper),
		),
		Verifier: verificationapp.NewVerifyDocument(
			verificationinfra.NewPDFVerifier(),
			verificationinfra.NewCadesVerifier(),
			verificationinfra.NewCachedTrustProvider(),
			realClock{},
		).WithXades(verificationinfra.NewXadesVerifier()),
		Files:   serve.RootedFiles{Roots: []string{root}},
		Token:   "test-token",
		Version: "9.9.9-test",
	}

	server := httptest.NewServer(service.Handler())
	t.Cleanup(server.Close)

	return fixture{service: service, server: server, token: "test-token", root: root}
}

// realClock reports the current time.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// call performs an authenticated request.
func (f fixture) call(t *testing.T, method, path string, body any, headers map[string]string) *http.Response {
	t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequest(method, f.server.URL+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("X-Firma-Token", f.token)
	for name, value := range headers {
		request.Header.Set(name, value)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

// problemOf decodes a problem+json body.
func problemOf(t *testing.T, response *http.Response) map[string]any {
	t.Helper()

	if contentType := response.Header.Get("Content-Type"); contentType != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", contentType)
	}
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	return body
}

// TestStatusIsUnauthenticated: a health check must not need a secret.
func TestStatusIsUnauthenticated(t *testing.T) {
	fixture := newFixture(t)

	response, err := http.Get(fixture.server.URL + "/status")
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status body = %v", body)
	}
}

// TestVersionHasTheAgreedShape pins the response the project fixed.
func TestVersionHasTheAgreedShape(t *testing.T) {
	fixture := newFixture(t)

	response, err := http.Get(fixture.server.URL + "/version")
	if err != nil {
		t.Fatalf("GET /version: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	var body struct {
		Data struct {
			Version string `json:"version"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.Version != "9.9.9-test" {
		t.Errorf("version = %q", body.Data.Version)
	}
}

// TestPrivilegedRoutesNeedTheToken is the first defence.
func TestPrivilegedRoutesNeedTheToken(t *testing.T) {
	fixture := newFixture(t)

	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/v1/signatures"},
		{"PUT", "/v1/signatures/abc"},
		{"GET", "/v1/signatures/abc"},
		{"PUT", "/v1/verifications/abc"},
		{"GET", "/v1/verifications/abc"},
	}

	for _, route := range routes {
		request, err := http.NewRequest(route.method, fixture.server.URL+route.path, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}

		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", route.method, route.path, err)
		}

		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a token = %d, want 401", route.method, route.path, response.StatusCode)
		}
		problem := problemOf(t, response)
		if problem["title"] != "token-required" {
			t.Errorf("title = %v", problem["title"])
		}
		_ = response.Body.Close()
	}
}

// TestWrongTokenIsRejected covers the comparison itself.
func TestWrongTokenIsRejected(t *testing.T) {
	fixture := newFixture(t)

	response := fixture.call(t, "GET", "/v1/signatures", nil, map[string]string{
		"X-Firma-Token": "not-the-token",
	})
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", response.StatusCode)
	}
}

// TestCrossOriginIsRejected is the defence against drive-by signing: a browser
// sends Origin and cannot forge it, so a request from a page is refused.
func TestCrossOriginIsRejected(t *testing.T) {
	fixture := newFixture(t)

	for _, origin := range []string{"https://evil.example", "http://localhost:3000", "null"} {
		response := fixture.call(t, "GET", "/v1/signatures", nil, map[string]string{"Origin": origin})
		if response.StatusCode != http.StatusForbidden {
			t.Errorf("Origin %q = %d, want 403", origin, response.StatusCode)
		}
		problem := problemOf(t, response)
		if problem["title"] != "origin-rejected" {
			t.Errorf("Origin %q title = %v", origin, problem["title"])
		}
	}
}

// TestSameOriginIsAccepted keeps the previous test honest: the check must not
// reject the legitimate case.
func TestSameOriginIsAccepted(t *testing.T) {
	fixture := newFixture(t)

	request, err := http.NewRequest("GET", fixture.server.URL+"/v1/signatures", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("X-Firma-Token", fixture.token)
	// The Origin a browser sends for a same-origin request.
	request.Header.Set("Origin", fixture.server.URL)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		t.Errorf("same-origin request = %d, want 200", response.StatusCode)
	}
}

// TestPathOutsideRootIsRefused: the API must not become a file read primitive.
func TestPathOutsideRootIsRefused(t *testing.T) {
	fixture := newFixture(t)

	response := fixture.call(t, "PUT", "/v1/signatures/job", map[string]any{
		"path":   "/etc/passwd",
		"format": "xades",
		"level":  "bes",
		"pem":    "/etc/passwd",
	}, nil)

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.StatusCode)
	}
	problem := problemOf(t, response)
	if problem["title"] != "path-rejected" {
		t.Errorf("title = %v", problem["title"])
	}
}

// TestSymlinkEscapingTheRootIsRefused: a prefix check on the literal path would
// accept a link inside the root that points outside it.
func TestSymlinkEscapingTheRootIsRefused(t *testing.T) {
	fixture := newFixture(t)

	target := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	link := filepath.Join(fixture.root, "link.xml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}

	response := fixture.call(t, "PUT", "/v1/signatures/job", map[string]any{
		"path":   link,
		"format": "xades",
		"level":  "bes",
		"pem":    link,
	}, nil)

	if response.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403: the link points outside the root", response.StatusCode)
	}
}

// TestInvalidIdentifierIsRefused keeps path separators out of the route.
func TestInvalidIdentifierIsRefused(t *testing.T) {
	fixture := newFixture(t)

	for _, identifier := range []string{"..", "a/b", "a space", strings.Repeat("x", 65)} {
		response := fixture.call(t, "PUT", "/v1/signatures/"+identifier, map[string]any{}, nil)
		if response.StatusCode == http.StatusOK {
			t.Errorf("identifier %q was accepted", identifier)
		}
	}
}

// TestSigningOverHTTPProducesAVerifiableFile is the end-to-end case.
func TestSigningOverHTTPProducesAVerifiableFile(t *testing.T) {
	fixture := newFixture(t)

	certificate, key := fixture.material(t)
	document := filepath.Join(fixture.root, "doc.xml")
	if err := os.WriteFile(document, []byte(`<?xml version="1.0"?><atto><n>1</n></atto>`), 0o600); err != nil {
		t.Fatalf("write document: %v", err)
	}
	bundle := filepath.Join(fixture.root, "bundle.pem")
	if err := os.WriteFile(bundle, append(certificate, key...), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	response := fixture.call(t, "PUT", "/v1/signatures/job-1", map[string]any{
		"path":   document,
		"format": "xades",
		"level":  "bes",
		"pem":    bundle,
	}, nil)

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("sign = %d: %s", response.StatusCode, body)
	}

	var signed struct {
		ID   string `json:"id"`
		Path string `json:"path"`
		Size int    `json:"size"`
	}
	if err := json.NewDecoder(response.Body).Decode(&signed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if signed.ID != "job-1" || signed.Size == 0 {
		t.Errorf("response = %+v", signed)
	}

	// The produced file must actually verify.
	if _, err := os.Stat(signed.Path); err != nil {
		t.Fatalf("the signed file does not exist: %v", err)
	}

	reports, err := verificationinfra.NewXadesVerifier().Extract(signed.Path)
	if err != nil {
		t.Fatalf("verify the produced file: %v", err)
	}
	if reports[0].Integrity != verification.StatusGood {
		t.Errorf("integrity = %s, the file served over HTTP must be valid", reports[0].Integrity)
	}
}

// TestVerificationIsCachedForRetrieval covers the one piece of state.
func TestVerificationIsCachedForRetrieval(t *testing.T) {
	fixture := newFixture(t)

	certificate, key := fixture.material(t)
	document := filepath.Join(fixture.root, "doc.xml")
	if err := os.WriteFile(document, []byte(`<?xml version="1.0"?><b>2</b>`), 0o600); err != nil {
		t.Fatalf("write document: %v", err)
	}
	bundle := filepath.Join(fixture.root, "bundle.pem")
	if err := os.WriteFile(bundle, append(certificate, key...), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	signed := fixture.call(t, "PUT", "/v1/signatures/job-2", map[string]any{
		"path": document, "format": "xades", "level": "bes", "pem": bundle,
	}, nil)
	var artefact struct {
		Path string `json:"path"`
	}
	_ = json.NewDecoder(signed.Body).Decode(&artefact)
	_ = signed.Body.Close()

	verificationResponse := fixture.call(t, "PUT", "/v1/verifications/check-1", map[string]any{
		"path": artefact.Path,
	}, nil)
	if verificationResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(verificationResponse.Body)
		t.Fatalf("verify = %d: %s", verificationResponse.StatusCode, body)
	}

	var report map[string]any
	_ = json.NewDecoder(verificationResponse.Body).Decode(&report)
	_ = verificationResponse.Body.Close()
	if report["id"] != "check-1" || report["verdict"] == nil {
		t.Errorf("report = %v", report)
	}

	// And it can be read back.
	retrieved := fixture.call(t, "GET", "/v1/verifications/check-1", nil, nil)
	if retrieved.StatusCode != http.StatusOK {
		t.Errorf("retrieval = %d, want 200", retrieved.StatusCode)
	}
}

// TestUnknownVerificationIs404 keeps the error honest.
func TestUnknownVerificationIs404(t *testing.T) {
	fixture := newFixture(t)

	response := fixture.call(t, "GET", "/v1/verifications/missing", nil, nil)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", response.StatusCode)
	}
}

// TestSignatureIsNotRetained: the GET route says so instead of pretending.
func TestSignatureIsNotRetained(t *testing.T) {
	fixture := newFixture(t)

	response := fixture.call(t, "GET", "/v1/signatures/anything", nil, nil)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", response.StatusCode)
	}
}

// TestBindingOutsideLoopbackIsRefused is the mitigation that stops the API from
// becoming a network service.
func TestBindingOutsideLoopbackIsRefused(t *testing.T) {
	service := &serve.Service{Token: "x", Files: serve.RootedFiles{}}

	for _, address := range []string{"0.0.0.0:0", ":0", "192.168.1.10:8080"} {
		if _, err := service.Listen(context.Background(), address); err == nil {
			t.Errorf("address %q was accepted; only loopback may be used", address)
		}
	}
}

// TestTokenFileIsPrivate checks the file mode a caller depends on.
func TestTokenFileIsPrivate(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "run")

	path, err := serve.WriteToken(directory, "secret")
	if err != nil {
		t.Fatalf("WriteToken: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(content) != "secret" {
		t.Errorf("content = %q", content)
	}
}

// material issues a certificate and key for the test.
func (f fixture) material(t *testing.T) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "HTTP Test Signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// unusedSigner keeps the signingdomain import meaningful if the tests change.
var _ = signingdomain.BES

// writeFile puts content in the allowed root and returns its path.
func (f fixture) writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()

	path := filepath.Join(f.root, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// readAllString reads a response body as a string.
func readAllString(t *testing.T, response *http.Response) string {
	t.Helper()

	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(content)
}
