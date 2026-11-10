package infrastructure

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/encryption/application"
	"codeberg.org/simplicer/trebaruna/src/encryption/infrastructure/ldap"
	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// LDAPDirectory finds certificates in an LDAP directory: ldap://host or
// ldaps://host (TLS), with the search base in the URL's path or in Base.
// The connection is recorded among the program's, as a directory lookup.
type LDAPDirectory struct {
	URL  string
	Base string
	// TLS secures ldaps://; nil checks the server against the system's
	// roots.
	TLS *tls.Config
}

// Find returns the certificates published for who, an e-mail address or a
// common name; one the directory holds that cannot be read is left out.
func (d LDAPDirectory) Find(ctx context.Context, who string) ([]*x509.Certificate, error) {
	address, base, secured, err := d.endpoint()
	if err != nil {
		return nil, err
	}
	scheme := "ldap"
	if secured != nil {
		scheme = "ldaps"
	}
	connection, err := transparency.Dial(ctx, transparencydomain.PurposeDirectory, scheme, address, secured)
	if err != nil {
		return nil, fmt.Errorf("reach the directory %s: %w", address, err)
	}
	defer connection.Close()
	values, err := ldap.Search(ctx, connection, base, who)
	if err != nil {
		return nil, err
	}
	var certificates []*x509.Certificate
	for _, value := range values {
		if certificate, err := x509.ParseCertificate(value); err == nil {
			certificates = append(certificates, certificate)
		}
	}
	return certificates, nil
}

// endpoint reads the URL: the address with its port, the search base, and
// the TLS configuration for ldaps.
func (d LDAPDirectory) endpoint() (string, string, *tls.Config, error) {
	parsed, err := url.Parse(d.URL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") {
		return "", "", nil, fmt.Errorf("a directory is ldap://host or ldaps://host, not %q", d.URL)
	}
	port := "389"
	var secured *tls.Config
	if parsed.Scheme == "ldaps" {
		port = "636"
		secured = d.TLS
		if secured == nil {
			secured = &tls.Config{}
		}
		secured = secured.Clone()
		if secured.ServerName == "" {
			secured.ServerName = parsed.Hostname()
		}
		secured.MinVersion = tls.VersionTLS12
	}
	if parsed.Port() != "" {
		port = parsed.Port()
	}
	base := d.Base
	if base == "" {
		base, _ = url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	}
	return net.JoinHostPort(parsed.Hostname(), port), base, secured, nil
}

// compile-time proof that the adapter satisfies the port.
var _ application.CertificateDirectory = LDAPDirectory{}
