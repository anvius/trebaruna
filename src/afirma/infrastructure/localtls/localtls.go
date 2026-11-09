// Package localtls makes and installs the certificate trebaruna serves the
// afirma:// local channels with (ADR-0019): WebSocket on 127.0.0.1, which
// pages reach only over TLS.
//
// The root that issues it is made per user, signs the server certificate
// once and its private key is discarded at once, never written anywhere: no
// other certificate can ever be issued under it. Its name constraints,
// marked critical, also limit it to 127.0.0.1 and localhost. Installing the
// root in the user's browser stores is a separate, explicit step, undone by
// Remove; the system's stores are never touched.
package localtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Nickname names the root in the browsers' stores.
const Nickname = "trebaruna local channel (127.0.0.1)"

// validity is how long the root and the server certificate last; a new pair
// is made, and installed again, when they expire.
const validity = 3 * 365 * 24 * time.Hour

const (
	rootFile   = "root.pem"
	serverFile = "server.pem"
	keyFile    = "server.key"
)

// ErrMissing means no certificate was made yet.
var ErrMissing = errors.New("no local channel certificate yet: run `trebaruna afirma local-tls install`")

// Material is the root and the server certificate with its key.
type Material struct {
	Root   *x509.Certificate
	Server tls.Certificate
}

// Fingerprint is the root's SHA-256, as the person can compare it.
func (m Material) Fingerprint() string {
	digest := sha256.Sum256(m.Root.Raw)
	return hex.EncodeToString(digest[:])
}

// Directory is where the material lives: $XDG_CONFIG_HOME/trebaruna/localtls.
func Directory() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "trebaruna", "localtls"), nil
}

// Generate makes a new root and server certificate in directory, replacing
// any there. The root's key exists only inside this function.
func Generate(directory string, now time.Time) (Material, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, err
	}
	loopback := net.IPNet{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(32, 32)}
	rootTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{Organization: []string{"trebaruna"},
			CommonName: "trebaruna local channel root (127.0.0.1 only, key destroyed)"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(validity),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedIPRanges:           []*net.IPNet{&loopback},
		PermittedDNSDomains:         []string{"localhost"},
		PermittedDNSDomainsCritical: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return Material{}, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return Material{}, err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{Organization: []string{"trebaruna"}, CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, root, &serverKey.PublicKey, rootKey)
	// The root's key goes out of scope here and is never stored.
	if err != nil {
		return Material{}, err
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return Material{}, err
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Material{}, err
	}
	certificates := append(pemOf("CERTIFICATE", serverDER), pemOf("CERTIFICATE", rootDER)...)
	for name, content := range map[string][]byte{
		rootFile:   pemOf("CERTIFICATE", rootDER),
		serverFile: certificates,
		keyFile:    pemOf("PRIVATE KEY", serverKeyDER),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			return Material{}, err
		}
	}
	return Load(directory)
}

// Load reads the material made earlier.
func Load(directory string) (Material, error) {
	rootPEM, err := os.ReadFile(filepath.Join(directory, rootFile))
	if errors.Is(err, os.ErrNotExist) {
		return Material{}, ErrMissing
	}
	if err != nil {
		return Material{}, err
	}
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		return Material{}, fmt.Errorf("%s holds no certificate", rootFile)
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Material{}, err
	}
	server, err := tls.LoadX509KeyPair(filepath.Join(directory, serverFile), filepath.Join(directory, keyFile))
	if err != nil {
		return Material{}, err
	}
	return Material{Root: root, Server: server}, nil
}

// Expired reports material that no longer serves at now (or within a day).
func (m Material) Expired(now time.Time) bool {
	return now.Add(24 * time.Hour).After(m.Root.NotAfter)
}

// RootPEM is the root as the stores import it.
func (m Material) RootPEM() []byte { return pemOf("CERTIFICATE", m.Root.Raw) }

func pemOf(kind string, der []byte) []byte {
	var out bytes.Buffer
	_ = pem.Encode(&out, &pem.Block{Type: kind, Bytes: der})
	return out.Bytes()
}

func randomSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}
