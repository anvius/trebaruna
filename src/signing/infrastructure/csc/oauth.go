package csc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// OAuth runs the OAuth2 authorisation-code flow a CSC service offers for
// signing in (scope "service") and for authorising one signature (scope
// "credential"): the person authorises in their own browser, the
// authorisation server sends the browser back to this computer with a
// code, and the code becomes a token. PKCE (RFC 7636, S256) binds the code
// to this process and a random state to this request; the browser comes
// back to a loopback address only (RFC 8252).
type OAuth struct {
	// Base is the service's OAuth2 base (info's oauth2).
	Base string
	// ClientID names trebaruna to the provider; ClientSecret is empty for a
	// public client.
	ClientID     string
	ClientSecret string
	// Redirect is the loopback address the browser comes back to, such as
	// http://127.0.0.1:8765/callback; empty, or port 0, takes a free port
	// on 127.0.0.1.
	Redirect string
	HTTP     *http.Client
	// Open shows the authorisation page to the person.
	Open func(address string) error
}

// ErrOAuth is an authorisation the person or the server did not give.
var ErrOAuth = errors.New("the OAuth2 authorisation did not complete")

// ServiceToken signs the person in.
func (o OAuth) ServiceToken(ctx context.Context) (string, error) {
	return o.token(ctx, url.Values{"scope": {"service"}})
}

// CredentialToken authorises the signature of the hashes with the
// credential; signatures/signHash takes it in place of the activation data.
func (o OAuth) CredentialToken(ctx context.Context, credentialID string, hashes [][]byte, hashOID string) (string, error) {
	encoded := make([]string, len(hashes))
	for index, hash := range hashes {
		encoded[index] = base64.RawURLEncoding.EncodeToString(hash)
	}
	return o.token(ctx, url.Values{
		"scope":            {"credential"},
		"credentialID":     {credentialID},
		"numSignatures":    {fmt.Sprint(len(hashes))},
		"hashes":           {strings.Join(encoded, ",")},
		"hashAlgorithmOID": {hashOID},
	})
}

// token sends the person to the authorisation page, waits for their
// browser to come back with the code and exchanges it.
func (o OAuth) token(ctx context.Context, parameters url.Values) (string, error) {
	// The code and the client's proof travel to the server: over TLS, or
	// on this computer.
	base, err := url.Parse(o.Base)
	if err != nil || (base.Scheme != "https" && !(base.Scheme == "http" && loopback(base.Hostname()))) {
		return "", fmt.Errorf("the service's OAuth2 server is not https: %q", o.Base)
	}
	listener, redirect, err := o.listen()
	if err != nil {
		return "", err
	}
	defer listener.Close()

	verifier := randomText(32)
	challenge := sha256.Sum256([]byte(verifier))
	state := randomText(16)
	parameters.Set("response_type", "code")
	parameters.Set("client_id", o.ClientID)
	parameters.Set("redirect_uri", redirect.String())
	parameters.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	parameters.Set("code_challenge_method", "S256")
	parameters.Set("state", state)

	codes := make(chan callback, 1)
	server := &http.Server{Handler: callbackHandler(redirect.Path, state, codes)}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	if err := o.Open(o.Base + "/oauth2/authorize?" + parameters.Encode()); err != nil {
		return "", err
	}
	var code string
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("%w: nobody authorised in the browser in time", ErrOAuth)
	case answer := <-codes:
		if answer.err != nil {
			return "", answer.err
		}
		code = answer.code
	}
	return o.exchange(ctx, code, redirect.String(), verifier)
}

// listen opens the loopback address the browser comes back to.
func (o OAuth) listen() (net.Listener, *url.URL, error) {
	redirect, err := url.Parse(o.Redirect)
	if o.Redirect == "" {
		redirect, err = url.Parse("http://127.0.0.1:0/callback")
	}
	if err != nil || redirect.Scheme != "http" || !loopback(redirect.Hostname()) {
		return nil, nil, fmt.Errorf("the OAuth2 redirect must be an http address on this computer (127.0.0.1): %q", o.Redirect)
	}
	host := redirect.Hostname()
	if host == "localhost" {
		host = "127.0.0.1"
	}
	port := redirect.Port()
	if port == "" {
		port = "0"
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, nil, fmt.Errorf("listen for the OAuth2 redirect: %w", err)
	}
	if port == "0" {
		redirect.Host = listener.Addr().String()
	}
	if redirect.Path == "" {
		redirect.Path = "/"
	}
	return listener, redirect, nil
}

type callback struct {
	code string
	err  error
}

// callbackHandler takes the browser's return: the code, if the state is
// this request's; the server's refusal otherwise. The first answer counts.
func callbackHandler(path, state string, codes chan<- callback) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != path {
			http.NotFound(writer, request)
			return
		}
		query := request.URL.Query()
		var answer callback
		switch {
		case subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(state)) != 1:
			answer.err = fmt.Errorf("%w: the browser came back with another request's state", ErrOAuth)
		case query.Get("error") != "":
			answer.err = fmt.Errorf("%w: %s %s", ErrOAuth, query.Get("error"), query.Get("error_description"))
		case query.Get("code") == "":
			answer.err = fmt.Errorf("%w: the browser came back without a code", ErrOAuth)
		default:
			answer.code = query.Get("code")
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if answer.err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(writer, "trebaruna: the authorisation did not complete. You can close this page.")
		} else {
			fmt.Fprintln(writer, "trebaruna: authorised. You can close this page and go back to trebaruna.")
		}
		select {
		case codes <- answer:
		default:
		}
	})
}

// exchange trades the code for a token (RFC 6749, 4.1.3), proving with the
// verifier that this process asked for it.
func (o OAuth) exchange(ctx context.Context, code, redirect, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {o.ClientID},
		"code_verifier": {verifier},
	}
	if o.ClientSecret != "" {
		form.Set("client_secret", o.ClientSecret)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Base+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := o.HTTP.Do(request)
	if err != nil {
		return "", fmt.Errorf("oauth2/token: %w", err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("oauth2/token: %w", err)
	}
	var answer struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(content, &answer)
	if response.StatusCode != http.StatusOK || answer.AccessToken == "" {
		return "", fmt.Errorf("%w: oauth2/token answered %d %s %s", ErrOAuth, response.StatusCode, answer.Error, answer.Description)
	}
	return answer.AccessToken, nil
}

func loopback(host string) bool {
	return host == "localhost" || net.ParseIP(host).IsLoopback()
}

// randomText is base64url of random bytes: a PKCE verifier or a state.
func randomText(size int) string {
	buffer := make([]byte, size)
	_, _ = rand.Read(buffer)
	return base64.RawURLEncoding.EncodeToString(buffer)
}
