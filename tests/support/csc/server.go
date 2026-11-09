// Package csc is a Cloud Signature Consortium API v2 service for tests: two
// credentials with keys in memory, and the checks a real provider makes.
//
//   - rsa-explicit: RSA 2048 under a test CA, authorised with a PIN for each
//     signature, described in v2's shape, accepting only rsaEncryption with
//     a separate hash (so the client must not assume the combined OID).
//   - ecdsa-implicit: ECDSA P-256, self-signed, authorised implicitly,
//     described in v1's shape, answering signatures as raw r||s.
//
// Every call but auth/login needs the bearer token; activation data (SAD)
// is single use and bound to the hashes it authorised.
package csc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
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
)

// Server is the running service.
type Server struct {
	// URL is the API base (…/csc/v2).
	URL string
	// CA signed rsa-explicit's certificate.
	CA *x509.Certificate

	mu          sync.Mutex
	sads        map[string]authorised
	credentials map[string]*credential
	calls       []string
}

type authorised struct {
	credential string
	hashes     []string
}

type credential struct {
	key      crypto.Signer
	chain    [][]byte
	explicit bool
	v1       bool
	raw      bool
	algo     []string
}

// Start runs the service for the test's lifetime.
func Start(t *testing.T) *Server {
	t.Helper()
	server := &Server{sads: map[string]authorised{}, credentials: map[string]*credential{}}

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

	httpServer := httptest.NewServer(http.HandlerFunc(server.serve))
	t.Cleanup(httpServer.Close)
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
	endpoint := strings.TrimPrefix(request.URL.Path, "/csc/v2/")
	s.mu.Lock()
	s.calls = append(s.calls, endpoint)
	s.mu.Unlock()

	var body map[string]any
	_ = json.NewDecoder(request.Body).Decode(&body)
	if endpoint == "auth/login" {
		user, password, ok := request.BasicAuth()
		if !ok || user != User || password != Password {
			refuse(writer, http.StatusUnauthorized, "invalid_request", "bad credentials")
			return
		}
		answer(writer, map[string]any{"access_token": Token, "expires_in": 3600})
		return
	}
	if request.Header.Get("Authorization") != "Bearer "+Token {
		refuse(writer, http.StatusUnauthorized, "invalid_token", "no or wrong access token")
		return
	}
	switch endpoint {
	case "credentials/list":
		answer(writer, map[string]any{"credentialIDs": []string{"ecdsa-implicit", "rsa-explicit"}})
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
