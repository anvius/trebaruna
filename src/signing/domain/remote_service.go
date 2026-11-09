package domain

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// ErrInvalidRemoteService means a CSC service that cannot be used.
var ErrInvalidRemoteService = errors.New("invalid remote signing service")

// RemoteService is a Cloud Signature Consortium API v2 service: where it
// answers, which credential (key and certificate) signs, and how to sign in
// and authorise. The secrets travel in the environment, never on the
// command line (ADR-0006).
type RemoteService struct {
	// Address is the API's base, such as https://provider.example/csc/v2.
	Address string
	// Credential names the credential; empty when the service holds one.
	Credential string
	// Token is an access token; User and Password sign in when there is
	// none.
	Token    string
	User     string
	Password string
	// PIN and OTP authorise each signature, when the credential asks.
	PIN string
	OTP string
	// OAuthClient names trebaruna to the provider's OAuth2 server, for a
	// sign-in or a signature the person authorises in their browser;
	// OAuthSecret is empty for a public client. OAuthRedirect is the
	// loopback address the browser comes back to (empty: any free port).
	OAuthClient   string
	OAuthSecret   string
	OAuthRedirect string
}

// validate refuses a service that is not an HTTPS address: the hash and the
// authorisation travel to it. Plain HTTP is accepted only on this computer,
// for tests.
func (r RemoteService) validate() error {
	address, err := url.Parse(strings.TrimSpace(r.Address))
	if err != nil || address.Host == "" {
		return errors.Join(ErrInvalidRemoteService, errors.New("the address must be a URL"))
	}
	if address.Scheme != "https" && !(address.Scheme == "http" && onThisComputer(address)) {
		return errors.Join(ErrInvalidRemoteService, errors.New("the address must be https"))
	}
	if r.OAuthRedirect == "" {
		return nil
	}
	// The browser brings the authorisation code back: only to this computer.
	redirect, err := url.Parse(r.OAuthRedirect)
	if err != nil || redirect.Scheme != "http" || !onThisComputer(redirect) {
		return errors.Join(ErrInvalidRemoteService, errors.New("the OAuth2 redirect must be an http address on this computer"))
	}
	return nil
}

func onThisComputer(address *url.URL) bool {
	host := address.Hostname()
	return host == "localhost" || net.ParseIP(host).IsLoopback()
}

// Host names the provider in receipts: a remote signature says where its
// key is.
func (r RemoteService) Host() string {
	if address, err := url.Parse(r.Address); err == nil {
		return address.Host
	}
	return r.Address
}
