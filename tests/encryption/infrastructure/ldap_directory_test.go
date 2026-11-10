package infrastructure_test

// A recipient's certificates found in an LDAP directory: an anonymous bind,
// a search by mail or cn under the base the URL or Base names, the
// certificate attributes of the entries, over ldap:// or ldaps://, the
// connection recorded as a directory lookup. The test directory reads the
// requests with encoding/asn1.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/encryption/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/encryption/infrastructure/ldap"
	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
	"codeberg.org/simplicer/trebaruna/tests/support/ldapserver"
)

func TestARecipientIsFoundInAnLDAPDirectory(t *testing.T) {
	encryption, signing := certificateFor(t, "MARIA LOPEZ"), certificateFor(t, "MARIA LOPEZ (firma)")
	server := ldapserver.Start(t, nil,
		ldapserver.Entry{DN: "cn=Maria Lopez,o=Example,c=ES", Mail: "maria@example.org", CN: "Maria Lopez",
			Certificates: [][]byte{encryption.Raw, signing.Raw, []byte("not a certificate")}},
		ldapserver.Entry{DN: "cn=Luca Verdi,o=Example,c=ES", Mail: "luca@example.org", CN: "Luca Verdi",
			Attribute: "userCertificate", Certificates: [][]byte{certificateFor(t, "LUCA VERDI").Raw}})
	transparency.Reset()

	found, err := infrastructure.LDAPDirectory{URL: "ldap://" + server.Address + "/o=Example,c=ES"}.Find(context.Background(), "maria@example.org")
	if err != nil || len(found) != 2 || !found[0].Equal(encryption) || !found[1].Equal(signing) {
		t.Fatalf("found %d: %v", len(found), err)
	}
	searches := server.Searches()
	if len(searches) != 1 || searches[0].Base != "o=Example,c=ES" || searches[0].Scope != 2 ||
		len(searches[0].Values) != 2 || searches[0].Values[0] != "mail=maria@example.org" || searches[0].Values[1] != "cn=maria@example.org" ||
		len(searches[0].Attributes) != len(ldap.CertificateAttributes) {
		t.Errorf("the directory was asked %+v", searches)
	}
	if server.Binds() != 1 || waitFor(func() bool { return server.Unbinds() == 1 }) != nil {
		t.Errorf("binds %d, unbinds %d", server.Binds(), server.Unbinds())
	}
	recorded := transparency.Connections()
	if len(recorded) != 1 || recorded[0].Purpose != transparencydomain.PurposeDirectory || recorded[0].URL != "ldap://"+server.Address+"/" ||
		recorded[0].SentBytes == 0 || recorded[0].Received == 0 {
		t.Errorf("recorded %+v", recorded)
	}

	// By name, the base given apart, under the plain attribute.
	byName, err := infrastructure.LDAPDirectory{URL: "ldap://" + server.Address, Base: "o=Example,c=ES"}.Find(context.Background(), "Luca Verdi")
	if err != nil || len(byName) != 1 || byName[0].Subject.CommonName != "LUCA VERDI" {
		t.Errorf("by name: %d %v", len(byName), err)
	}
	nobody, err := infrastructure.LDAPDirectory{URL: "ldap://" + server.Address + "/o=Example"}.Find(context.Background(), "nadie@example.org")
	if err != nil || len(nobody) != 0 {
		t.Errorf("nobody: %d %v", len(nobody), err)
	}
}

func TestADirectoryOverTLSIsCheckedAndUsed(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	raw, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	server := ldapserver.Start(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: key}}},
		ldapserver.Entry{DN: "cn=Maria", Mail: "maria@example.org", Certificates: [][]byte{certificateFor(t, "MARIA").Raw}})
	trusted, _ := x509.ParseCertificate(raw)
	roots := x509.NewCertPool()
	roots.AddCert(trusted)

	found, err := infrastructure.LDAPDirectory{URL: "ldaps://" + server.Address, Base: "o=Example", TLS: &tls.Config{RootCAs: roots}}.Find(context.Background(), "maria@example.org")
	if err != nil || len(found) != 1 {
		t.Errorf("over TLS: %d %v", len(found), err)
	}
	// A server the system does not trust is refused.
	if _, err := (infrastructure.LDAPDirectory{URL: "ldaps://" + server.Address, Base: "o=Example"}).Find(context.Background(), "maria@example.org"); err == nil {
		t.Error("an untrusted directory was used")
	}
}

func TestADirectoryThatRefusesSaysSo(t *testing.T) {
	refusing := ldapserver.Start(t, nil)
	refusing.BindResult = 49 // invalidCredentials
	if _, err := (infrastructure.LDAPDirectory{URL: "ldap://" + refusing.Address + "/o=Example"}).Find(context.Background(), "x"); !errors.Is(err, ldap.ErrDirectory) {
		t.Errorf("a refused bind: %v", err)
	}
	missing := ldapserver.Start(t, nil)
	missing.SearchResult = 32 // noSuchObject
	if _, err := (infrastructure.LDAPDirectory{URL: "ldap://" + missing.Address + "/o=Nowhere"}).Find(context.Background(), "x"); !errors.Is(err, ldap.ErrDirectory) {
		t.Errorf("a base that does not exist: %v", err)
	}
	// More matches than the directory sends: what it sent is kept.
	limited := ldapserver.Start(t, nil, ldapserver.Entry{DN: "cn=Maria", Mail: "maria@example.org", Certificates: [][]byte{certificateFor(t, "MARIA").Raw}})
	limited.SearchResult = 4
	if found, err := (infrastructure.LDAPDirectory{URL: "ldap://" + limited.Address + "/o=Example"}).Find(context.Background(), "maria@example.org"); err != nil || len(found) != 1 {
		t.Errorf("a size limit: %d %v", len(found), err)
	}
	// Without a port, LDAP's and LDAPS's own: nothing listens on them here,
	// and the connection recorded says where it went.
	for url, wanted := range map[string]string{"ldap://127.0.0.1/o=Example": "ldap://127.0.0.1:389/", "ldaps://127.0.0.1/o=Example": "ldaps://127.0.0.1:636/"} {
		transparency.Reset()
		(infrastructure.LDAPDirectory{URL: url}).Find(context.Background(), "x")
		if recorded := transparency.Connections(); len(recorded) != 1 || recorded[0].URL != wanted {
			t.Errorf("%s went to %+v, want %s", url, recorded, wanted)
		}
	}
	for _, address := range []string{"http://example.org", "ldap:///o=Example", "maria@example.org"} {
		if _, err := (infrastructure.LDAPDirectory{URL: address}).Find(context.Background(), "x"); err == nil {
			t.Errorf("%s was taken for a directory", address)
		}
	}
}

// waitFor polls a condition the server sets in its own goroutine.
func waitFor(condition func() bool) error {
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if condition() {
			return nil
		}
	}
	return errors.New("timed out")
}
