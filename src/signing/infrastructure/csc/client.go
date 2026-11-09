// Package csc speaks the Cloud Signature Consortium API v2 (ADR-0014): the
// open interface remote signing providers expose. Only what signing needs
// is implemented: sign in, list and describe credentials, authorise a
// signature over given hashes, and have the provider sign them. Hashes
// leave this computer; documents and keys do not cross.
package csc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrService is a failure the service reported.
var ErrService = errors.New("the remote signing service refused")

// Client talks to one CSC service.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// NewClient prepares a client for the service at base (…/csc/v2).
func NewClient(base string, client *http.Client) *Client {
	return &Client{base: strings.TrimRight(base, "/"), http: client}
}

// UseToken signs every call with an access token.
func (c *Client) UseToken(token string) { c.token = token }

// WithToken is a copy of the client that signs its calls with another
// token: a credential-scoped one, which authorises one signature.
func (c *Client) WithToken(token string) *Client {
	copied := *c
	copied.token = token
	return &copied
}

// Service is what a CSC service says of itself (info): how it signs
// people in, and where its OAuth2 authorisation server is.
type Service struct {
	AuthTypes []string
	// OAuth2 is the base of the authorisation server's endpoints
	// (…/oauth2/authorize, …/oauth2/token).
	OAuth2 string
}

// Info asks the service to describe itself; it needs no sign-in.
func (c *Client) Info(ctx context.Context) (Service, error) {
	var answer struct {
		AuthType []string `json:"authType"`
		OAuth2   string   `json:"oauth2"`
	}
	if err := c.call(ctx, "info", map[string]any{}, &answer, nil); err != nil {
		return Service{}, err
	}
	return Service{AuthTypes: answer.AuthType, OAuth2: strings.TrimRight(answer.OAuth2, "/")}, nil
}

// Login signs in with a user and a password (auth/login, HTTP Basic) and
// keeps the access token it returns.
func (c *Client) Login(ctx context.Context, user, password string) error {
	var answer struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.call(ctx, "auth/login", map[string]any{}, &answer, func(request *http.Request) {
		request.SetBasicAuth(user, password)
	}); err != nil {
		return err
	}
	if answer.AccessToken == "" {
		return fmt.Errorf("%w: auth/login returned no access token", ErrService)
	}
	c.token = answer.AccessToken
	return nil
}

// Credentials lists the credentials the account holds.
func (c *Client) Credentials(ctx context.Context) ([]string, error) {
	var answer struct {
		CredentialIDs []string `json:"credentialIDs"`
	}
	err := c.call(ctx, "credentials/list", map[string]any{"maxResults": 100}, &answer, nil)
	return answer.CredentialIDs, err
}

// Credential describes a credential: its certificates, its key, and what
// authorising a signature with it takes.
type Credential struct {
	// Certificates are DER, the signer's first.
	Certificates [][]byte
	KeyEnabled   bool
	CertValid    bool
	// KeyAlgorithms are the signature algorithms the key accepts, by OID.
	KeyAlgorithms []string
	// Explicit says the credential asks for a PIN or an OTP to authorise;
	// NeedsPIN and NeedsOTP say which.
	Explicit bool
	NeedsPIN bool
	NeedsOTP bool
	// OAuth says each signature is authorised by the person in their
	// browser, through the service's OAuth2 server (oauth2code).
	OAuth bool
}

// credentialAnswer reads both shapes of credentials/info: v2's auth object
// and v1's authMode, PIN and OTP.
type credentialAnswer struct {
	Key struct {
		Status string   `json:"status"`
		Algo   []string `json:"algo"`
	} `json:"key"`
	Cert struct {
		Status       string   `json:"status"`
		Certificates []string `json:"certificates"`
	} `json:"cert"`
	Auth struct {
		Mode    string `json:"mode"`
		Objects []struct {
			ID string `json:"id"`
		} `json:"objects"`
	} `json:"auth"`
	AuthMode string `json:"authMode"`
	PIN      struct {
		Presence string `json:"presence"`
	} `json:"PIN"`
	OTP struct {
		Presence string `json:"presence"`
	} `json:"OTP"`
}

// Credential reads credentials/info, asking for the whole chain.
func (c *Client) Credential(ctx context.Context, id string) (Credential, error) {
	var answer credentialAnswer
	request := map[string]any{"credentialID": id, "certificates": "chain", "certInfo": true, "authInfo": true}
	if err := c.call(ctx, "credentials/info", request, &answer, nil); err != nil {
		return Credential{}, err
	}
	mode := answer.Auth.Mode
	if mode == "" {
		mode = answer.AuthMode
	}
	credential := Credential{
		OAuth:         mode == "oauth2code",
		KeyEnabled:    answer.Key.Status == "" || answer.Key.Status == "enabled",
		CertValid:     answer.Cert.Status == "" || answer.Cert.Status == "valid",
		KeyAlgorithms: answer.Key.Algo,
	}
	for _, encoded := range answer.Cert.Certificates {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return Credential{}, fmt.Errorf("%w: a certificate of %s is not Base64", ErrService, id)
		}
		credential.Certificates = append(credential.Certificates, der)
	}
	credential.Explicit = mode == "explicit"
	for _, object := range answer.Auth.Objects {
		switch strings.ToUpper(object.ID) {
		case "PIN":
			credential.NeedsPIN = true
		case "OTP":
			credential.NeedsOTP = true
		}
	}
	credential.NeedsPIN = credential.NeedsPIN || answer.PIN.Presence == "true"
	credential.NeedsOTP = credential.NeedsOTP || answer.OTP.Presence == "true"
	return credential, nil
}

// Authorize obtains the signature activation data (SAD) for the hashes,
// with the PIN and OTP the credential asks for.
func (c *Client) Authorize(ctx context.Context, id string, hashes [][]byte, hashOID, pin, otp string) (string, error) {
	request := map[string]any{
		"credentialID": id, "numSignatures": len(hashes), "hashes": encode(hashes), "hashAlgorithmOID": hashOID,
	}
	if pin != "" {
		request["PIN"] = pin
	}
	if otp != "" {
		request["OTP"] = otp
	}
	var answer struct {
		SAD string `json:"SAD"`
	}
	if err := c.call(ctx, "credentials/authorize", request, &answer, nil); err != nil {
		return "", err
	}
	if answer.SAD == "" {
		return "", fmt.Errorf("%w: credentials/authorize returned no activation data", ErrService)
	}
	return answer.SAD, nil
}

// SignHash has the service sign the hashes with the credential's key. sad
// is empty for a credential authorised implicitly, which sends none.
func (c *Client) SignHash(ctx context.Context, id, sad string, hashes [][]byte, hashOID, signatureOID string) ([][]byte, error) {
	request := map[string]any{
		"credentialID": id, "hashes": encode(hashes), "hashAlgorithmOID": hashOID, "signAlgo": signatureOID,
	}
	if sad != "" {
		request["SAD"] = sad
	}
	var answer struct {
		Signatures []string `json:"signatures"`
	}
	if err := c.call(ctx, "signatures/signHash", request, &answer, nil); err != nil {
		return nil, err
	}
	if len(answer.Signatures) != len(hashes) {
		return nil, fmt.Errorf("%w: %d signatures for %d hashes", ErrService, len(answer.Signatures), len(hashes))
	}
	signatures := make([][]byte, 0, len(answer.Signatures))
	for _, encoded := range answer.Signatures {
		signature, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: a signature is not Base64", ErrService)
		}
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

// call posts JSON to an endpoint and reads the JSON answer, or the CSC
// error it carries.
func (c *Client) call(ctx context.Context, endpoint string, body any, answer any, prepare func(*http.Request)) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/"+endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	if prepare != nil {
		prepare(request)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %w", endpoint, err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("%s: %w", endpoint, err)
	}
	if response.StatusCode != http.StatusOK {
		var refusal struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(content, &refusal)
		return fmt.Errorf("%w: %s answered %d %s %s", ErrService, endpoint, response.StatusCode, refusal.Error, refusal.Description)
	}
	if err := json.Unmarshal(content, answer); err != nil {
		return fmt.Errorf("%w: %s answered something that is not its JSON", ErrService, endpoint)
	}
	return nil
}

// encode writes hashes in Base64, as CSC carries them.
func encode(hashes [][]byte) []string {
	encoded := make([]string, len(hashes))
	for index, hash := range hashes {
		encoded[index] = base64.StdEncoding.EncodeToString(hash)
	}
	return encoded
}
