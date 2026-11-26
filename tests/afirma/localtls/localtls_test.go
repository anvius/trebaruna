package localtls_test

// The certificate the afirma:// local channels serve on 127.0.0.1
// (ADR-0019): issued by a root whose key no file holds, limited by critical
// name constraints to 127.0.0.1 and localhost, and trusted only in the NSS
// stores it is installed in.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/localtls"
	"codeberg.org/simplicer/trebaruna/tests/support/portable"
)

func TestTheRootSignsOnlyTheLocalServerAndKeepsNoKey(t *testing.T) {
	directory := t.TempDir()
	material, err := localtls.Generate(directory, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	root := material.Root
	if !root.IsCA || !root.MaxPathLenZero || len(root.PermittedIPRanges) != 1 || root.PermittedIPRanges[0].String() != "127.0.0.1/32" ||
		strings.Join(root.PermittedDNSDomains, ",") != "localhost" {
		t.Errorf("root constraints: CA %v, path %v, IPs %v, DNS %v", root.IsCA, root.MaxPathLenZero, root.PermittedIPRanges, root.PermittedDNSDomains)
	}
	critical := false
	for _, extension := range root.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 30}) {
			critical = extension.Critical
		}
	}
	if !critical {
		t.Error("the name constraints must be critical")
	}

	// One private key on disk, the server's.
	entries, _ := os.ReadDir(directory)
	keys := 0
	for _, entry := range entries {
		content, _ := os.ReadFile(filepath.Join(directory, entry.Name()))
		keys += strings.Count(string(content), "PRIVATE KEY-----") / 2
		if info, _ := entry.Info(); portable.PosixModes() && info.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v, want 0600", entry.Name(), info.Mode().Perm())
		}
	}
	if keys != 1 {
		t.Errorf("%d private keys on disk, want the server's alone", keys)
	}
	leaf, _ := x509.ParseCertificate(material.Server.Certificate[0])
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(material.Server.PrivateKey.(*ecdsa.PrivateKey).Public()) {
		t.Error("the key on disk is not the server's")
	}

	pool := x509.NewCertPool()
	pool.AddCert(root)
	for _, name := range []string{"127.0.0.1", "localhost"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTheConstraintsRefuseAnyOtherName: a root with these constraints
// cannot vouch for a real site, even with a key (ours has none).
func TestTheConstraintsRefuseAnyOtherName(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	loopback := net.IPNet{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(32, 32)}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "constrained"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, PermittedIPRanges: []*net.IPNet{&loopback}, PermittedDNSDomains: []string{"localhost"},
		PermittedDNSDomainsCritical: true}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	root, _ := x509.ParseCertificate(der)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"sede.example.gob.es"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, root, &leafKey.PublicKey, key)
	leaf, _ := x509.ParseCertificate(leafDER)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "sede.example.gob.es"}); err == nil {
		t.Error("a name outside the constraints verified")
	}
}

// TestATLSClientTrustsTheServerOnlyThroughTheRoot.
func TestATLSClientTrustsTheServerOnlyThroughTheRoot(t *testing.T) {
	material, err := localtls.Generate(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{material.Server}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.(*tls.Conn).Handshake()
			connection.Close()
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(material.Root)
	for name, config := range map[string]*tls.Config{"the root": {RootCAs: pool}, "the system's roots": {}} {
		connection, err := tls.Dial("tcp", listener.Addr().String(), config)
		if (err == nil) != (name == "the root") {
			t.Errorf("trusting %s: %v", name, err)
		}
		if connection != nil {
			connection.Close()
		}
	}
}

// TestAStoreWithoutAnNSSDatabaseCannotBeChecked: a folder holding no store is
// a store that cannot be checked, and nothing is written to it.
func TestAStoreWithoutAnNSSDatabaseCannotBeChecked(t *testing.T) {
	folder := t.TempDir()
	if _, err := localtls.Check(folder); !errors.Is(err, localtls.ErrNoStore) {
		t.Errorf("check: %v", err)
	}
	material, err := localtls.Generate(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := localtls.Install(material, []string{folder}); !errors.Is(err, localtls.ErrNoStore) {
		t.Errorf("install: %v", err)
	}
	if entries, _ := os.ReadDir(folder); len(entries) != 0 {
		t.Errorf("the folder was written to: %d entries", len(entries))
	}
	if err := localtls.Remove([]string{folder}); err != nil {
		t.Errorf("removing from a folder with no store: %v", err)
	}
}
