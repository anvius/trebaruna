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
}

// validate refuses a service that is not an HTTPS address: the hash and the
// authorisation travel to it. Plain HTTP is accepted only on this computer,
// for tests.
func (r RemoteService) validate() error {
	address, err := url.Parse(strings.TrimSpace(r.Address))
	if err != nil || address.Host == "" {
		return errors.Join(ErrInvalidRemoteService, errors.New("the address must be a URL"))
	}
	switch address.Scheme {
	case "https":
		return nil
	case "http":
		host := address.Hostname()
		if host == "localhost" || net.ParseIP(host).IsLoopback() {
			return nil
		}
	}
	return errors.Join(ErrInvalidRemoteService, errors.New("the address must be https"))
}

// Host names the provider in receipts: a remote signature says where its
// key is.
func (r RemoteService) Host() string {
	if address, err := url.Parse(r.Address); err == nil {
		return address.Host
	}
	return r.Address
}
