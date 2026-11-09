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
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/localtls"
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
		if info, _ := entry.Info(); info.Mode().Perm() != 0o600 {
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

// TestTheRootGoesInAndOutOfAnNSSStore, as Firefox and Chromium keep them.
func TestTheRootGoesInAndOutOfAnNSSStore(t *testing.T) {
	if _, err := exec.LookPath("certutil"); err != nil {
		t.Skip("certutil is not installed")
	}
	database := t.TempDir()
	if output, err := exec.Command("certutil", "-N", "-d", "sql:"+database, "--empty-password").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, output)
	}
	material, err := localtls.Generate(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := localtls.Install(material, []string{database}); err != nil {
		t.Fatal(err)
	}
	listing, _ := exec.Command("certutil", "-L", "-d", "sql:"+database).CombinedOutput()
	if !strings.Contains(string(listing), localtls.Nickname) || !strings.Contains(string(listing), "C,,") || !localtls.Installed(database) {
		t.Errorf("not installed as a server authority:\n%s", listing)
	}
	// Installing again replaces it.
	if err := localtls.Install(material, []string{database}); err != nil {
		t.Fatal(err)
	}
	if listing, _ := exec.Command("certutil", "-L", "-d", "sql:"+database).CombinedOutput(); strings.Count(string(listing), localtls.Nickname) != 1 {
		t.Errorf("installed twice:\n%s", listing)
	}
	if err := localtls.Remove([]string{database}); err != nil || localtls.Installed(database) {
		t.Errorf("still installed: %v", err)
	}
}
