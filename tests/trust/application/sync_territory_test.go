package application_test

// SyncTerritory reads the EU list of the lists once for a whole sync: it is
// half a megabyte, and it was downloaded again for every territory.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	trustapplication "codeberg.org/simplicer/trebaruna/src/trust/application"
)

// pointer is one OtherTSLPointer of a LOTL.
func pointer(territory, location, certificate string) string {
	return `<TSPService><ServiceInformation><OtherTSLPointer>` +
		`<ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>` + certificate +
		`</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>` +
		`<TSLLocation>` + location + `</TSLLocation><AdditionalInformation>` +
		`<OtherInformation><SchemeTerritory>` + territory + `</SchemeTerritory></OtherInformation>` +
		`</AdditionalInformation></OtherTSLPointer></ServiceInformation></TSPService>`
}

func lotlWith(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Operator"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := base64.StdEncoding.EncodeToString(der)
	return []byte(`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><SchemeInformation>` +
		`<NextUpdate>2027-04-15T00:00:00Z</NextUpdate></SchemeInformation><TrustServiceProviderList>` +
		`<TrustServiceProvider><TSPServices>` +
		pointer("AA", "https://example.invalid/AA.xml", certificate) +
		pointer("BB", "https://example.invalid/BB.xml", certificate) +
		pointer("CC", "https://example.invalid/CC.pdf", certificate) +
		`</TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`)
}

// countedLOTL serves the LOTL, failing the first fetches it is told to.
type countedLOTL struct {
	content []byte
	fail    int
	fetches int
}

func (l *countedLOTL) Fetch() ([]byte, error) {
	l.fetches++
	if l.fetches <= l.fail {
		return nil, errors.New("network down")
	}
	return l.content, nil
}

// unsignedLists serves a list without a signature.
type unsignedLists struct{}

func (unsignedLists) Fetch(string) ([]byte, error) {
	return []byte(`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>`), nil
}

func TestTheEUListIsFetchedOncePerSync(t *testing.T) {
	source := &countedLOTL{content: lotlWith(t)}
	syncer := &trustapplication.SyncTerritory{LOTL: source, Lists: unsignedLists{}}

	territories, err := syncer.Territories()
	if err != nil || !slices.Equal(territories, []string{"AA", "BB"}) {
		t.Fatalf("territories %v, %v: the PDF-only one is left out", territories, err)
	}
	for _, territory := range territories {
		result, err := syncer.Execute(territory)
		if err != nil || result.Authenticated || result.Written {
			t.Errorf("%s: %+v %v", territory, result, err)
		}
	}
	if _, err := syncer.Territory("ZZ"); err == nil {
		t.Error("a territory the list does not name")
	}
	if source.fetches != 1 {
		t.Errorf("the EU list was fetched %d times", source.fetches)
	}
}

func TestAFailedFetchOfTheEUListIsTriedAgain(t *testing.T) {
	source := &countedLOTL{content: lotlWith(t), fail: 1}
	syncer := &trustapplication.SyncTerritory{LOTL: source, Lists: unsignedLists{}}
	if _, err := syncer.Execute("AA"); err == nil {
		t.Fatal("the first fetch fails")
	}
	if entry, err := syncer.Territory("AA"); err != nil || entry.Location != "https://example.invalid/AA.xml" {
		t.Errorf("%+v %v", entry, err)
	}
	if source.fetches != 2 {
		t.Errorf("fetched %d times, want 2", source.fetches)
	}
}
