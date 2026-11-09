// Package csc is a Cloud Signature Consortium API v2 service for tests: two
// credentials with keys in memory, and the checks a real provider makes.
//
//   - rsa-explicit: RSA 2048 under a test CA, authorised with a PIN for each
//     signature, described in v2's shape, accepting only rsaEncryption with
//     a separate hash (so the client must not assume the combined OID).
//   - ecdsa-implicit: ECDSA P-256, self-signed, authorised implicitly,
//     described in v1's shape, answering signatures as raw r||s.
//   - rsa-oauth: RSA 2048 under the test CA, each signature authorised in
//     the browser through the OAuth2 server (oauth2code).
//
// Every call but info and auth/login needs the bearer token; activation
// data (SAD) and credential-scoped tokens are single use and bound to the
// hashes they authorised. The OAuth2 server at the service's root sends
// the browser straight back with a code, as if the person had agreed (or
// refused, with Refuse), and checks PKCE when the code is exchanged.
package csc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Credentials and secrets the service knows.
const (
	Token    = "test-access-token"
	User     = "mario"
	Password = "segreto"
	PIN      = "123456"
	// OAuthClient is the client id the OAuth2 server knows.
	OAuthClient = "trebaruna-test"
)

// Server is the running service.
type Server struct {
	// URL is the API base (…/csc/v2).
	URL string
	// CA signed rsa-explicit's certificate.
	CA *x509.Certificate

	// Refuse makes the OAuth2 server answer as if the person refused.
	Refuse bool

	mu          sync.Mutex
	sads        map[string]authorised
	credentials map[string]*credential
	calls       []string
	codes       map[string]grant
	// scoped are credential-scoped access tokens, each for one signature.
	scoped map[string]authorised
	root   string
}

// grant is what an authorisation code was given for.
type grant struct {
	challenge, redirect, scope string
	authorised                 authorised
}

type authorised struct {
	credential string
	hashes     []string
}

type credential struct {
	key      crypto.Signer
	chain    [][]byte
	explicit bool
	oauth    bool
	v1       bool
	raw      bool
	algo     []string
}

// Start runs the service for the test's lifetime.
func Start(t *testing.T) *Server {
	t.Helper()
	server := &Server{sads: map[string]authorised{}, credentials: map[string]*credential{},
		codes: map[string]grant{}, scoped: map[string]authorised{}}

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CSC TEST CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	server.CA, _ = x509.ParseCertificate(caDER)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "MARIO ROSSI (REMOTE)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, server.CA, &rsaKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	server.credentials["rsa-explicit"] = &credential{key: rsaKey, chain: [][]byte{leafDER, caDER}, explicit: true,
		algo: []string{"1.2.840.113549.1.1.1"}}

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "ANNA BIANCHI (REMOTE)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment}
	ecDER, _ := x509.CreateCertificate(rand.Reader, ecTemplate, ecTemplate, &ecKey.PublicKey, ecKey)
	server.credentials["ecdsa-implicit"] = &credential{key: ecKey, chain: [][]byte{ecDER}, v1: true, raw: true,
		algo: []string{"1.2.840.10045.4.3.2"}}

	oauthKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	oauthLeaf := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "LUCA VERDI (REMOTE)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment}
	oauthDER, _ := x509.CreateCertificate(rand.Reader, oauthLeaf, server.CA, &oauthKey.PublicKey, caKey)
	server.credentials["rsa-oauth"] = &credential{key: oauthKey, chain: [][]byte{oauthDER, caDER}, oauth: true,
		algo: []string{"1.2.840.113549.1.1.11"}}

	httpServer := httptest.NewServer(http.HandlerFunc(server.serve))
	t.Cleanup(httpServer.Close)
	server.root = httpServer.URL
	server.URL = httpServer.URL + "/csc/v2"
	return server
}

// Calls lists the endpoints called, in order.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.calls...)
}

func (s *Server) serve(writer http.ResponseWriter, request *http.Request) {
	endpoint := strings.TrimPrefix(strings.TrimPrefix(request.URL.Path, "/csc/v2/"), "/")
	s.mu.Lock()
	s.calls = append(s.calls, endpoint)
	s.mu.Unlock()

	switch endpoint {
	case "oauth2/authorize":
		s.oauthAuthorize(writer, request)
		return
	case "oauth2/token":
		s.oauthToken(writer, request)
		return
	}
	var body map[string]any
	_ = json.NewDecoder(request.Body).Decode(&body)
	if endpoint == "info" {
		answer(writer, map[string]any{"specs": "2.0.0.2", "name": "CSC test", "authType": []string{"basic", "oauth2code"}, "oauth2": s.root + "/"})
		return
	}
	if endpoint == "auth/login" {
		user, password, ok := request.BasicAuth()
		if !ok || user != User || password != Password {
			refuse(writer, http.StatusUnauthorized, "invalid_request", "bad credentials")
			return
		}
		answer(writer, map[string]any{"access_token": Token, "expires_in": 3600})
		return
	}
	bearer := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	if endpoint == "signatures/signHash" && bearer != Token {
		s.signHashScoped(writer, body, bearer)
		return
	}
	if bearer != Token {
		refuse(writer, http.StatusUnauthorized, "invalid_token", "no or wrong access token")
		return
	}
	switch endpoint {
	case "credentials/list":
		answer(writer, map[string]any{"credentialIDs": []string{"ecdsa-implicit", "rsa-explicit", "rsa-oauth"}})
	case "credentials/info":
		s.info(writer, body)
	case "credentials/authorize":
		s.authorize(writer, body)
	case "signatures/signHash":
		s.signHash(writer, body)
	default:
		refuse(writer, http.StatusNotFound, "invalid_request", endpoint)
	}
}

func (s *Server) info(writer http.ResponseWriter, body map[string]any) {
	id, _ := body["credentialID"].(string)
	credential, known := s.credentials[id]
	if !known {
		refuse(writer, http.StatusBadRequest, "invalid_request", "unknown credential")
		return
	}
	certificates := make([]string, len(credential.chain))
	for index, der := range credential.chain {
		certificates[index] = base64.StdEncoding.EncodeToString(der)
	}
	described := map[string]any{
		"key":  map[string]any{"status": "enabled", "algo": credential.algo},
		"cert": map[string]any{"status": "valid", "certificates": certificates},
	}
	switch {
	case credential.v1:
		described["authMode"] = "implicit"
		described["PIN"] = map[string]any{"presence": "false"}
	case credential.oauth:
		described["auth"] = map[string]any{"mode": "oauth2code"}
	default:
		described["auth"] = map[string]any{"mode": "explicit", "objects": []map[string]any{{"type": "Password", "id": "PIN", "format": "N"}}}
	}
	answer(writer, described)
}

func (s *Server) authorize(writer http.ResponseWriter, body map[string]any) {
	id, _ := body["credentialID"].(string)
	if body["PIN"] != PIN {
		refuse(writer, http.StatusBadRequest, "invalid_pin", "wrong PIN")
		return
	}
	sad := base64.StdEncoding.EncodeToString(random(16))
	s.mu.Lock()
	s.sads[sad] = authorised{credential: id, hashes: texts(body["hashes"])}
	s.mu.Unlock()
	answer(writer, map[string]any{"SAD": sad, "expiresIn": 300})
}

func (s *Server) signHash(writer http.ResponseWriter, body map[string]any) {
	id, _ := body["credentialID"].(string)
	credential, known := s.credentials[id]
	if !known {
		refuse(writer, http.StatusBadRequest, "invalid_request", "unknown credential")
		return
	}
	hashes := texts(body["hashes"])
	if credential.oauth {
		refuse(writer, http.StatusBadRequest, "invalid_request", "this credential signs with a credential-scoped token only")
		return
	}
	if credential.explicit {
		sad, _ := body["SAD"].(string)
		s.mu.Lock()
		granted, valid := s.sads[sad]
		delete(s.sads, sad)
		s.mu.Unlock()
		if !valid || granted.credential != id || !slices.Equal(granted.hashes, hashes) {
			refuse(writer, http.StatusBadRequest, "invalid_request", "the activation data does not authorise these hashes")
			return
		}
	}
	s.sign(writer, credential, body, hashes)
}

// signHashScoped signs with a credential-scoped token in place of the
// service's: once, for the credential and hashes it was given for.
func (s *Server) signHashScoped(writer http.ResponseWriter, body map[string]any, bearer string) {
	id, _ := body["credentialID"].(string)
	hashes := texts(body["hashes"])
	s.mu.Lock()
	granted, valid := s.scoped[bearer]
	delete(s.scoped, bearer)
	s.mu.Unlock()
	credential, known := s.credentials[id]
	if !valid || !known || granted.credential != id || !slices.Equal(granted.hashes, hashes) {
		refuse(writer, http.StatusUnauthorized, "invalid_token", "the token does not authorise these hashes")
		return
	}
	s.sign(writer, credential, body, hashes)
}

func (s *Server) sign(writer http.ResponseWriter, credential *credential, body map[string]any, hashes []string) {
	algorithm, _ := body["signAlgo"].(string)
	if !slices.Contains(credential.algo, algorithm) {
		refuse(writer, http.StatusBadRequest, "invalid_request", "signAlgo "+algorithm+" is not this key's")
		return
	}
	var signatures []string
	for _, encoded := range hashes {
		hash, _ := base64.StdEncoding.DecodeString(encoded)
		var signature []byte
		var err error
		switch key := credential.key.(type) {
		case *rsa.PrivateKey:
			signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash)
		case *ecdsa.PrivateKey:
			r, sValue, signErr := ecdsa.Sign(rand.Reader, key, hash)
			err = signErr
			signature = append(r.FillBytes(make([]byte, 32)), sValue.FillBytes(make([]byte, 32))...)
		}
		if err != nil {
			refuse(writer, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		signatures = append(signatures, base64.StdEncoding.EncodeToString(signature))
	}
	answer(writer, map[string]any{"signatures": signatures})
}

// oauthAuthorize is the person's visit to the authorisation page: agreed
// (or refused) at once, the browser sent back to the loopback redirect.
func (s *Server) oauthAuthorize(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	redirect, err := url.Parse(query.Get("redirect_uri"))
	switch {
	case query.Get("client_id") != OAuthClient, query.Get("response_type") != "code",
		query.Get("code_challenge_method") != "S256", query.Get("code_challenge") == "",
		err != nil || redirect.Scheme != "http" || !strings.HasPrefix(redirect.Host, "127.0.0.1:"):
		refuse(writer, http.StatusBadRequest, "invalid_request", "not an authorisation request this server takes")
		return
	}
	back := redirect.Query()
	back.Set("state", query.Get("state"))
	if s.Refuse {
		back.Set("error", "access_denied")
		redirect.RawQuery = back.Encode()
		http.Redirect(writer, request, redirect.String(), http.StatusFound)
		return
	}
	given := grant{challenge: query.Get("code_challenge"), redirect: query.Get("redirect_uri"), scope: query.Get("scope")}
	if given.scope == "credential" {
		given.authorised.credential = query.Get("credentialID")
		for _, encoded := range strings.Split(query.Get("hashes"), ",") {
			hash, _ := base64.RawURLEncoding.DecodeString(encoded)
			given.authorised.hashes = append(given.authorised.hashes, base64.StdEncoding.EncodeToString(hash))
		}
	}
	code := base64.RawURLEncoding.EncodeToString(random(16))
	s.mu.Lock()
	s.codes[code] = given
	s.mu.Unlock()
	back.Set("code", code)
	redirect.RawQuery = back.Encode()
	http.Redirect(writer, request, redirect.String(), http.StatusFound)
}

// oauthToken exchanges a code, once, for the client that proves with its
// verifier it asked for it.
func (s *Server) oauthToken(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil || request.Method != http.MethodPost {
		refuse(writer, http.StatusBadRequest, "invalid_request", "a form POST")
		return
	}
	s.mu.Lock()
	given, known := s.codes[request.PostForm.Get("code")]
	delete(s.codes, request.PostForm.Get("code"))
	s.mu.Unlock()
	verifier := sha256.Sum256([]byte(request.PostForm.Get("code_verifier")))
	switch {
	case !known, request.PostForm.Get("grant_type") != "authorization_code",
		request.PostForm.Get("client_id") != OAuthClient, request.PostForm.Get("redirect_uri") != given.redirect:
		refuse(writer, http.StatusBadRequest, "invalid_grant", "unknown or mismatched code")
		return
	case base64.RawURLEncoding.EncodeToString(verifier[:]) != given.challenge:
		refuse(writer, http.StatusBadRequest, "invalid_grant", "the verifier does not match the challenge")
		return
	}
	if given.scope != "credential" {
		answer(writer, map[string]any{"access_token": Token, "token_type": "Bearer", "expires_in": 3600})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(random(16))
	s.mu.Lock()
	s.scoped[token] = given.authorised
	s.mu.Unlock()
	answer(writer, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 300})
}

func answer(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func refuse(writer http.ResponseWriter, status int, code, description string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": code, "error_description": description})
}

func random(size int) []byte {
	buffer := make([]byte, size)
	_, _ = rand.Read(buffer)
	return buffer
}

// texts reads a JSON array of strings.
func texts(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		text, _ := item.(string)
		out = append(out, text)
	}
	return out
}
