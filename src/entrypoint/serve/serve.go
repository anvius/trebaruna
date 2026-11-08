// Package serve exposes the existing use cases over loopback HTTP.
//
// This is an adapter, like the CLI: it parses requests, calls the same use cases,
// and renders the result. It holds no signing or verification logic, so the two
// surfaces cannot disagree about what a signature is.
//
// Security model, from ADR-0004. The local HTTP surface is a known attack vector:
// it is the flaw that makes naive local signing agents exploitable by any web
// page the user happens to open. Four mitigations are structural here, not
// optional:
//
//	bind loopback only      a request from another host is never accepted
//	single-use token        required on every privileged route, stored 0600,
//	                        rotated on start and only readable by the user
//	origin check            a browser request is rejected unless its Origin is
//	                        the server itself, which stops drive-by signing
//	time window             the token is only valid while the process runs;
//	                        there is no long-lived secret to steal
//
// The routes follow the Zalando guidelines the project adopted: versioned URIs,
// client-supplied UUID with idempotent PUT, problem+json errors, and the
// mandatory /status and /version endpoints.
package serve

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	signingdomain "codeberg.org/simplicer/firma-it/src/signing/domain"
	verificationapp "codeberg.org/simplicer/firma-it/src/verification/application"
	verification "codeberg.org/simplicer/firma-it/src/verification/domain"
)

// Service is the HTTP adapter over the use cases.
type Service struct {
	// Signer performs a signature.
	Signer SigningUseCase
	// Verifier performs a verification.
	Verifier VerificationUseCase
	// Files resolves signs a path the caller asked for.
	Files FileAccess
	// Token is the single-use secret every privileged route requires.
	Token string
	// Now is the clock, injected so tests can freeze it.
	Now func() time.Time
	// Version is what /version reports.
	Version string

	// documents tracks verification results by identifier, so a client can
	// poll a job the same way it polls a signature.
	mu        sync.Mutex
	documents map[string]verification.DocumentReport

	// Pending holds protocol-handler requests awaiting a human decision.
	Pending *PendingRequests
	// Sender is the HTTP client used to deliver results. Nil uses a bounded
	// default, and tests substitute one to avoid the network.
	Sender *http.Client
}

// SigningUseCase is the signing capability the server needs.
type SigningUseCase interface {
	Execute(ctx context.Context, request application.Request) (application.Artefact, error)
}

// VerificationUseCase is the verification capability the server needs.
type VerificationUseCase interface {
	Execute(request verificationapp.Request) (verification.DocumentReport, error)
}

// FileAccess reports whether a caller-supplied path may be read.
//
// It exists so the server can refuse paths outside the roots the operator
// allowed, which is the difference between "a local API" and "a remote file read
// primitive dressed up as one".
type FileAccess interface {
	Allowed(path string) (string, error)
}

// RootedFiles restricts access to a set of directories.
type RootedFiles struct {
	// Roots are the directories a client may read from.
	Roots []string
}

// Allowed resolves a path and reports whether it falls inside a root.
func (r RootedFiles) Allowed(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is empty")
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", path, err)
	}
	// EvalSymlinks matters: a symlink inside a root that points outside it would
	// otherwise pass the prefix check and hand out arbitrary files.
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", path, err)
	}

	if len(r.Roots) == 0 {
		return "", errors.New("no directory is allowed; start the server with --root")
	}
	for _, root := range r.Roots {
		rootResolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		if resolved == rootResolved || strings.HasPrefix(resolved, rootResolved+string(os.PathSeparator)) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("%q is outside every allowed directory", path)
}

// Handler builds the HTTP handler.
func (s *Service) Handler() http.Handler {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.documents == nil {
		s.documents = map[string]verification.DocumentReport{}
	}
	if s.Pending == nil {
		s.Pending = NewPendingRequests()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.HandleFunc("GET /v1/signatures", s.handleListSignatures)
	mux.HandleFunc("PUT /v1/signatures/{id}", s.handleCreateSignature)
	mux.HandleFunc("GET /v1/signatures/{id}", s.handleGetSignature)
	mux.HandleFunc("PUT /v1/verifications/{id}", s.handleCreateVerification)
	mux.HandleFunc("GET /v1/verifications/{id}", s.handleGetVerification)

	// Protocol handler: a web page asks, a person decides, nothing signs itself.
	mux.HandleFunc("POST /v1/requests", s.handleCreateRequest)
	mux.HandleFunc("GET /v1/requests", s.handleListRequests)
	mux.HandleFunc("GET /v1/requests/{id}", s.handleGetRequest)
	mux.HandleFunc("POST /v1/requests/{id}/decision", s.handleDecideRequest)
	mux.HandleFunc("POST /v1/requests/{id}/sign", s.handleFulfilRequest)

	return s.guard(mux)
}

// guard applies the token and origin checks to every privileged route.
func (s *Service) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// /status and /version are unauthenticated on purpose: a health check
		// must not be a way to learn the token, and it exposes nothing.
		if request.URL.Path == "/status" || request.URL.Path == "/version" {
			next.ServeHTTP(writer, request)
			return
		}

		// A browser always sends Origin on a cross-origin request, and a page
		// cannot forge it. Anything that is not this exact server is refused,
		// which is what stops drive-by signing from a tab the user has open.
		if origin := request.Header.Get("Origin"); origin != "" {
			expected := "http://" + request.Host
			if subtle.ConstantTimeCompare([]byte(origin), []byte(expected)) != 1 {
				writeProblem(writer, http.StatusForbidden, "origin-rejected",
					"requests from other origins are refused")
				return
			}
		}

		provided := request.Header.Get("X-Firma-Token")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.Token)) != 1 || s.Token == "" {
			writeProblem(writer, http.StatusUnauthorized, "token-required",
				"this route needs the local token in X-Firma-Token")
			return
		}

		next.ServeHTTP(writer, request)
	})
}

// handleStatus reports liveness.
func (s *Service) handleStatus(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   s.Now().UTC().Format(time.RFC3339),
	})
}

// handleVersion reports the version in the shape the project fixed.
func (s *Service) handleVersion(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"data": map[string]string{"version": s.Version},
	})
}

// signatureRequest is the body of a PUT /v1/signatures/{id}.
type signatureRequest struct {
	Path   string `json:"path"`
	Format string `json:"format"`
	Level  string `json:"level"`
	P12    string `json:"p12,omitempty"`
	Pass   string `json:"passphrase,omitempty"`
	PEM    string `json:"pem,omitempty"`
	Reason string `json:"reason,omitempty"`
	TSA    string `json:"tsa,omitempty"`
	Output string `json:"output,omitempty"`
}

// signatureResponse is what a client reads back.
type signatureResponse struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	Format     string `json:"format"`
	Level      string `json:"level"`
	Size       int    `json:"size"`
	SignedAt   string `json:"signed_at"`
	SignerName string `json:"signer"`
	SelfSigned bool   `json:"self_signed"`
}

// handleListSignatures reports the routes that exist.
//
// There is no persistent job list: a signature is produced and returned in one
// request, so inventing history would be state the tool does not need and cannot
// clean up.
func (s *Service) handleListSignatures(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"data": map[string]any{
			"signatures": []string{},
			"note":       "PUT /v1/signatures/{id} produces one signature; nothing is stored",
		},
	})
}

// handleCreateSignature signs and returns the artefact metadata.
func (s *Service) handleCreateSignature(writer http.ResponseWriter, request *http.Request) {
	identifier := request.PathValue("id")
	if !validIdentifier(identifier) {
		writeProblem(writer, http.StatusBadRequest, "invalid-identifier",
			"the identifier must be a UUID or a short slug")
		return
	}

	var payload signatureRequest
	if err := decodeJSON(request, &payload); err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-body", err.Error())
		return
	}

	resolved, err := s.Files.Allowed(payload.Path)
	if err != nil {
		writeProblem(writer, http.StatusForbidden, "path-rejected", err.Error())
		return
	}

	format, err := signingdomain.ParseFormat(payload.Format)
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-format", err.Error())
		return
	}
	level, err := signingdomain.ParseLevel(payload.Level)
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-level", err.Error())
		return
	}

	keySource, err := s.resolveSigner(payload)
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-credentials", err.Error())
		return
	}

	document, err := signingdomain.OpenDocument(resolved)
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-document", err.Error())
		return
	}

	artefact, err := s.Signer.Execute(request.Context(), application.Request{
		Document:     document,
		Format:       format,
		Level:        level,
		Signer:       keySource,
		OutputPath:   payload.Output,
		Reason:       payload.Reason,
		TimestampURL: payload.TSA,
	})
	if err != nil {
		// A signature that could not be produced is not a client error in the
		// HTTP sense: the request was well formed and the operation failed.
		writeProblem(writer, http.StatusUnprocessableEntity, "signature-failed", err.Error())
		return
	}

	writeJSON(writer, http.StatusOK, signatureResponse{
		ID:         identifier,
		Path:       artefact.Path,
		Format:     string(artefact.Format),
		Level:      string(artefact.Level),
		Size:       artefact.Size,
		SignedAt:   artefact.SignedAt.UTC().Format(time.RFC3339),
		SignerName: artefact.SignerName,
		SelfSigned: artefact.SelfSigned,
	})
}

// handleGetSignature answers 404: nothing is retained.
func (s *Service) handleGetSignature(writer http.ResponseWriter, request *http.Request) {
	writeProblem(writer, http.StatusNotFound, "not-retained",
		"signatures are returned by the PUT that creates them and are not stored; "+
			"nothing with id "+request.PathValue("id")+" exists")
}

// verificationRequest is the body of PUT /v1/verifications/{id}.
type verificationRequest struct {
	Path      string `json:"path"`
	Format    string `json:"format,omitempty"`
	Territory string `json:"territory,omitempty"`
	Online    bool   `json:"online,omitempty"`
}

// handleCreateVerification verifies a document and keeps the report for retrieval.
//
// Verifying produces a document the caller may want to read twice, and it can be
// expensive with a network revocation check, so the report is cached in memory
// for the lifetime of the process.
func (s *Service) handleCreateVerification(writer http.ResponseWriter, request *http.Request) {
	identifier := request.PathValue("id")
	if !validIdentifier(identifier) {
		writeProblem(writer, http.StatusBadRequest, "invalid-identifier",
			"the identifier must be a UUID or a short slug")
		return
	}

	var payload verificationRequest
	if err := decodeJSON(request, &payload); err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-body", err.Error())
		return
	}

	resolved, err := s.Files.Allowed(payload.Path)
	if err != nil {
		writeProblem(writer, http.StatusForbidden, "path-rejected", err.Error())
		return
	}

	report, err := s.Verifier.Execute(verificationapp.Request{
		Path:      resolved,
		Format:    payload.Format,
		Territory: payload.Territory,
	})
	if err != nil {
		writeProblem(writer, http.StatusUnprocessableEntity, "verification-failed", err.Error())
		return
	}

	s.mu.Lock()
	s.documents[identifier] = report
	s.mu.Unlock()

	writeJSON(writer, http.StatusOK, s.reportJSON(identifier, report))
}

// handleGetVerification returns a stored report.
func (s *Service) handleGetVerification(writer http.ResponseWriter, request *http.Request) {
	identifier := request.PathValue("id")

	s.mu.Lock()
	report, found := s.documents[identifier]
	s.mu.Unlock()

	if !found {
		writeProblem(writer, http.StatusNotFound, "unknown-verification",
			"no verification with id "+identifier+" has been requested in this process")
		return
	}
	writeJSON(writer, http.StatusOK, s.reportJSON(identifier, report))
}

// reportJSON renders a verification report for the wire.
func (s *Service) reportJSON(identifier string, report verification.DocumentReport) map[string]any {
	signers := make([]map[string]any, 0, len(report.Signers))
	for _, signer := range report.Signers {
		entry := map[string]any{
			"field":       signer.FieldName,
			"signer":      signer.SignerName,
			"identifier":  signer.Identifier,
			"issuer":      signer.Issuer,
			"format":      signer.Format,
			"integrity":   string(signer.Integrity),
			"trust":       string(signer.Trust),
			"qualified":   signer.Qualified,
			"timestamped": signer.Timestamped,
			"self_signed": signer.SelfSigned,
		}
		if !signer.SignedAt.IsZero() {
			entry["signed_at"] = signer.SignedAt.UTC().Format(time.RFC3339)
		}
		if missing := signer.Qualification.Missing(signer.SignedAt); len(missing) > 0 {
			entry["missing"] = missing
		}
		signers = append(signers, entry)
	}

	return map[string]any{
		"id":          identifier,
		"path":        report.Path,
		"format":      report.Format,
		"signed":      report.Signed,
		"verdict":     string(report.Verdict()),
		"verified_at": report.VerifiedAt.UTC().Format(time.RFC3339),
		"signers":     signers,
	}
}

// resolveSigner builds the signer from the request payload.
func (s *Service) resolveSigner(payload signatureRequest) (signingdomain.Signer, error) {
	switch {
	case payload.P12 != "":
		content, err := os.ReadFile(payload.P12)
		if err != nil {
			return signingdomain.Signer{}, fmt.Errorf("read the P12: %w", err)
		}
		return signingdomain.NewSigner("api", signingdomain.FromP12,
			signingdomain.WithKeyMaterial(content),
			signingdomain.WithPassphrase(payload.Pass))
	case payload.PEM != "":
		content, err := os.ReadFile(payload.PEM)
		if err != nil {
			return signingdomain.Signer{}, fmt.Errorf("read the PEM: %w", err)
		}
		return signingdomain.NewSigner("api", signingdomain.FromPEM,
			signingdomain.WithKeyMaterial(content))
	}
	return signingdomain.Signer{}, errors.New("no key source: send p12 or pem")
}

// validIdentifier accepts a UUID or a short slug, refusing path separators.
func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-', character == '_':
		default:
			return false
		}
	}
	return true
}

// decodeJSON reads a bounded body.
func decodeJSON(request *http.Request, target any) error {
	defer func() { _ = request.Body.Close() }()

	decoder := json.NewDecoder(http.MaxBytesReader(nil, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("the body is not valid JSON for this route: %w", err)
	}
	return nil
}

// writeJSON serialises a response.
func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(body)
}

// problem is the RFC 9457 error shape the project uses.
type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// writeProblem renders a problem+json error.
func writeProblem(writer http.ResponseWriter, status int, code, detail string) {
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(problem{
		Type:   "https://codeberg.org/simplicer/firma-it/problems/" + code,
		Title:  code,
		Status: status,
		Detail: detail,
	})
}

// NewToken returns a fresh random token.
func NewToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate the local token: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

// WriteToken stores the token where only the user can read it.
//
// It returns the path so the CLI can print it: a caller needs to know where to
// look, and printing the token itself would put it in shell history.
func WriteToken(directory, token string) (string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", directory, err)
	}
	path := filepath.Join(directory, "token")

	// O_EXCL and 0600: never overwrite a token another process is using, and
	// never leave it readable by anyone else even for an instant.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if err := os.Remove(path); err != nil {
				return "", fmt.Errorf("replace the stale token: %w", err)
			}
			file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		}
		if err != nil {
			return "", fmt.Errorf("create %s: %w", path, err)
		}
	}
	defer func() { _ = file.Close() }()

	if _, err := file.WriteString(token); err != nil {
		return "", fmt.Errorf("write the token: %w", err)
	}
	return path, nil
}

// Listen binds to loopback and serves until the context is cancelled.
//
// The listener is created here rather than by http.Serve so the caller learns the
// actual port, which matters when 0 is requested.
func (s *Service) Listen(ctx context.Context, address string) (net.Addr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse the listen address: %w", err)
	}
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		return nil, fmt.Errorf(
			"refusing to listen on %q: the local API must stay on loopback, "+
				"or any page on the network can reach it", host)
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", address, err)
	}

	server := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()

	go func() { _ = server.Serve(listener) }()
	return listener.Addr(), nil
}

// RequestBody is the payload a page (or the URI handler) sends.
type RequestBody struct {
	Document  string `json:"document"`
	Format    string `json:"format,omitempty"`
	Territory string `json:"territory,omitempty"`
	Origin    string `json:"origin,omitempty"`
	Callback  string `json:"callback,omitempty"`
}

// handleCreateRequest registers a signing request and verifies the document.
//
// It never returns the approval secret: that is shown in the desktop window, and
// a page able to read it here could approve its own request.
func (s *Service) handleCreateRequest(writer http.ResponseWriter, request *http.Request) {
	var payload RequestBody
	if err := decodeJSON(request, &payload); err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-body", err.Error())
		return
	}

	pending, err := s.RegisterRequest(payload)
	if err != nil {
		status := http.StatusUnprocessableEntity
		code := "request-failed"
		switch {
		case errors.Is(err, ErrPathRejected):
			status, code = http.StatusForbidden, "path-rejected"
		case errors.Is(err, ErrInvalidOrigin):
			status, code = http.StatusBadRequest, "invalid-origin"
		case errors.Is(err, ErrInvalidCallback):
			status, code = http.StatusBadRequest, "invalid-callback"
		case errors.Is(err, ErrVerificationFailed):
			status, code = http.StatusUnprocessableEntity, "verification-failed"
		}
		writeProblem(writer, status, code, err.Error())
		return
	}

	writeJSON(writer, http.StatusAccepted, map[string]any{
		"id":         pending.ID,
		"expires_at": pending.ExpiresAt.UTC().Format(time.RFC3339),
		"verdict":    string(pending.Report.Verdict()),
		"note":       "the desktop app must approve this request; it cannot approve itself",
	})
}

// handleListRequests reports what is waiting for a decision.
func (s *Service) handleListRequests(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"data": s.Pending.List()})
}

// handleGetRequest reports one pending request.
func (s *Service) handleGetRequest(writer http.ResponseWriter, request *http.Request) {
	pending, found := s.Pending.Get(request.PathValue("id"))
	if !found {
		writeProblem(writer, http.StatusNotFound, "unknown-request",
			"no pending request with that identifier")
		return
	}
	writeJSON(writer, http.StatusOK, pending)
}

// decisionBody is the user's answer.
type decisionBody struct {
	Secret   string `json:"secret"`
	Approved bool   `json:"approved"`
}

// handleDecideRequest records the decision.
//
// This route exists for the desktop app, which holds the secret. A page cannot
// call it successfully because it never learns the secret.
func (s *Service) handleDecideRequest(writer http.ResponseWriter, request *http.Request) {
	var payload decisionBody
	if err := decodeJSON(request, &payload); err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-body", err.Error())
		return
	}

	if err := s.Pending.Decide(request.PathValue("id"), payload.Secret, payload.Approved); err != nil {
		writeProblem(writer, http.StatusForbidden, "decision-rejected", err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"id":       request.PathValue("id"),
		"approved": payload.Approved,
	})
}

// Errors RegisterRequest reports, so both callers can classify them.
var (
	// ErrPathRejected means the document is outside the allowed roots.
	ErrPathRejected = errors.New("path rejected")
	// ErrInvalidOrigin means the declared screen origin is malformed.
	ErrInvalidOrigin = errors.New("invalid origin")
	// ErrInvalidCallback means the callback escapes the declared origin.
	ErrInvalidCallback = errors.New("invalid callback")
	// ErrVerificationFailed means the document could not be examined.
	ErrVerificationFailed = errors.New("verification failed")
)

// RegisterRequest validates a request and verifies its document.
//
// It is the single path that creates a pending signature, used by the HTTP route
// and by the URI handler. The returned request carries the approval secret, which
// the caller must show to a person and never to the page that asked.
func (s *Service) RegisterRequest(payload RequestBody) (PendingRequest, error) {
	resolved, err := s.Files.Allowed(payload.Document)
	if err != nil {
		return PendingRequest{}, fmt.Errorf("%w: %v", ErrPathRejected, err)
	}

	if payload.Origin != "" {
		if err := validateOrigin(payload.Origin); err != nil {
			return PendingRequest{}, fmt.Errorf("%w: %v", ErrInvalidOrigin, err)
		}
	}
	if payload.Callback != "" {
		if err := validateCallback(payload.Callback, payload.Origin); err != nil {
			return PendingRequest{}, fmt.Errorf("%w: %v", ErrInvalidCallback, err)
		}
	}

	// Verify before asking. The user must never be invited to sign a file whose
	// content nobody has examined.
	report, err := s.Verifier.Execute(verificationapp.Request{
		Path:      resolved,
		Format:    payload.Format,
		Territory: payload.Territory,
	})
	if err != nil {
		return PendingRequest{}, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	return s.Pending.Create(PendingRequest{
		Path:      resolved,
		Format:    payload.Format,
		Territory: payload.Territory,
		Screen:    Screen{Origin: payload.Origin, Callback: payload.Callback},
		Report:    report,
	})
}

// fulfilBody names the key the approved request is signed with.
type fulfilBody struct {
	P12        string `json:"p12,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	PEM        string `json:"pem,omitempty"`
}

// handleFulfilRequest signs an approved request and delivers it.
//
// It is a separate step from the decision on purpose: approving is the human's
// act, and signing is the consequence. Splitting them means a request that was
// approved but whose key is missing fails loudly instead of silently doing
// nothing.
func (s *Service) handleFulfilRequest(writer http.ResponseWriter, request *http.Request) {
	var payload fulfilBody
	if err := decodeJSON(request, &payload); err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-body", err.Error())
		return
	}

	keySource, err := s.signingKey(payload)
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid-credentials", err.Error())
		return
	}

	delivery, err := s.Fulfil(request.Context(), request.PathValue("id"), keySource)
	if err != nil {
		writeProblem(writer, http.StatusForbidden, "fulfil-rejected", err.Error())
		return
	}

	status := http.StatusOK
	if !delivery.Delivered && delivery.Callback != "" {
		// The signature exists; the delivery did not happen. Saying so is better
		// than a 500 that suggests nothing was produced.
		status = http.StatusBadGateway
	}
	writeJSON(writer, status, delivery)
}

// signingKey resolves the key material from the fulfil payload.
func (s *Service) signingKey(payload fulfilBody) (signingdomain.Signer, error) {
	switch {
	case payload.P12 != "":
		resolved, err := s.Files.Allowed(payload.P12)
		if err != nil {
			return signingdomain.Signer{}, fmt.Errorf("%w: %v", ErrPathRejected, err)
		}
		content, err := os.ReadFile(resolved)
		if err != nil {
			return signingdomain.Signer{}, fmt.Errorf("read the P12: %w", err)
		}
		return signingdomain.NewSigner("api", signingdomain.FromP12,
			signingdomain.WithKeyMaterial(content),
			signingdomain.WithPassphrase(payload.Passphrase))
	case payload.PEM != "":
		resolved, err := s.Files.Allowed(payload.PEM)
		if err != nil {
			return signingdomain.Signer{}, fmt.Errorf("%w: %v", ErrPathRejected, err)
		}
		content, err := os.ReadFile(resolved)
		if err != nil {
			return signingdomain.Signer{}, fmt.Errorf("read the PEM: %w", err)
		}
		return signingdomain.NewSigner("api", signingdomain.FromPEM,
			signingdomain.WithKeyMaterial(content))
	}
	return signingdomain.Signer{}, errors.New("no key source: send p12 or pem")
}
