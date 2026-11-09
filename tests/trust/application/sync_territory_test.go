package application_test

// SyncTerritory reads the EU list of the lists once for a whole sync, and
// uses it only when it is authenticated: signed whole with a certificate the
// Official Journal announced, or with one a chain of pivot lists announced
// after that notice. A territory code becomes a file name only when it is
// two capital letters.

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"crypto/x509"

	trustapplication "codeberg.org/simplicer/trebaruna/src/trust/application"
	"codeberg.org/simplicer/trebaruna/tests/support/trustlist"
)

const notice = "https://eur-lex.example/eli/C/2026/1/oj"

// pointer is one OtherTSLPointer of a LOTL.
func pointer(territory, location, tslType, certificate string) string {
	return `<TSPService><ServiceInformation><OtherTSLPointer>` +
		`<ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>` + certificate +
		`</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>` +
		`<TSLLocation>` + location + `</TSLLocation><AdditionalInformation>` +
		`<OtherInformation><TSLType>` + tslType + `</TSLType></OtherInformation>` +
		`<OtherInformation><SchemeTerritory>` + territory + `</SchemeTerritory></OtherInformation>` +
		`</AdditionalInformation></OtherTSLPointer></ServiceInformation></TSPService>`
}

const (
	generic = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"
	lotls   = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
)

// lotlText is a LOTL naming the announcements given, publishing signers in
// its pointer to itself, and pointing at AA, BB, CC (PDF only) and extra.
func lotlText(signers []trustlist.Operator, announcements []string, extra ...string) string {
	var uris, self strings.Builder
	for _, address := range announcements {
		uris.WriteString(`<URI xml:lang="en">` + address + `</URI>`)
	}
	for _, signer := range signers {
		self.WriteString(pointer("EU", "https://example.invalid/eu-lotl.xml", lotls, signer.Base64()))
	}
	operator := signers[0].Base64()
	return `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="lotl"><SchemeInformation>` +
		`<SchemeInformationURI>` + uris.String() + `</SchemeInformationURI>` +
		`<NextUpdate>2027-04-15T00:00:00Z</NextUpdate></SchemeInformation><TrustServiceProviderList>` +
		`<TrustServiceProvider><TSPServices>` + self.String() +
		pointer("AA", "https://example.invalid/AA.xml", generic, operator) +
		pointer("BB", "https://example.invalid/BB.xml", generic, operator) +
		pointer("CC", "https://example.invalid/CC.pdf", generic, operator) +
		strings.Join(extra, "") +
		`</TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`
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

// lists serves pivot lists by address, and an unsigned list for anything
// else.
type lists map[string][]byte

func (l lists) Fetch(address string) ([]byte, error) {
	if content, ok := l[address]; ok {
		return content, nil
	}
	return []byte(`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>`), nil
}

func syncer(source trustapplication.LOTLSource, served lists, anchors ...trustlist.Operator) *trustapplication.SyncTerritory {
	certificates := make([]*x509.Certificate, 0, len(anchors))
	for _, anchor := range anchors {
		certificates = append(certificates, anchor.Certificate)
	}
	return &trustapplication.SyncTerritory{LOTL: source, Lists: served, LOTLAnchors: certificates, AnchorAnnouncement: notice}
}

func TestTheEUListIsFetchedOncePerSync(t *testing.T) {
	commission := trustlist.NewOperator(t, "Commission")
	source := &countedLOTL{content: trustlist.Sign(t, lotlText([]trustlist.Operator{commission}, []string{notice}), commission)}
	sync := syncer(source, lists{}, commission)

	territories, err := sync.Territories()
	if err != nil || !slices.Equal(territories, []string{"AA", "BB"}) {
		t.Fatalf("territories %v, %v: the PDF-only one and the list itself are left out", territories, err)
	}
	for _, territory := range territories {
		result, err := sync.Execute(territory)
		if err != nil || result.Authenticated || result.Written {
			t.Errorf("%s: %+v %v", territory, result, err)
		}
	}
	if _, err := sync.Territory("ZZ"); err == nil {
		t.Error("a territory the list does not name")
	}
	if source.fetches != 1 {
		t.Errorf("the EU list was fetched %d times", source.fetches)
	}
}

func TestAFailedFetchOfTheEUListIsTriedAgain(t *testing.T) {
	commission := trustlist.NewOperator(t, "Commission")
	source := &countedLOTL{content: trustlist.Sign(t, lotlText([]trustlist.Operator{commission}, []string{notice}), commission), fail: 1}
	sync := syncer(source, lists{}, commission)
	if _, err := sync.Execute("AA"); err == nil {
		t.Fatal("the first fetch fails")
	}
	if entry, err := sync.Territory("AA"); err != nil || entry.Location != "https://example.invalid/AA.xml" {
		t.Errorf("%+v %v", entry, err)
	}
	if source.fetches != 2 {
		t.Errorf("fetched %d times, want 2", source.fetches)
	}
}

// TestTheEUListMustBeSignedWithAnAnnouncedKey: a list signed with another
// key, or not signed, or changed after signing, is not used, whatever the
// connection it came over.
func TestTheEUListMustBeSignedWithAnAnnouncedKey(t *testing.T) {
	commission, impostor := trustlist.NewOperator(t, "Commission"), trustlist.NewOperator(t, "Impostor")
	text := lotlText([]trustlist.Operator{impostor}, []string{notice})
	for name, content := range map[string][]byte{
		"signed by another key":   trustlist.Sign(t, text, impostor),
		"not signed":              []byte(text),
		"changed after it signed": []byte(strings.Replace(string(trustlist.Sign(t, lotlText([]trustlist.Operator{commission}, []string{notice}), commission)), "AA.xml", "evil.xml", 1)),
	} {
		if _, err := syncer(&countedLOTL{content: content}, lists{}, commission).Territories(); err == nil {
			t.Errorf("%s: the list was used", name)
		}
	}
}

// TestPivotListsLeadFromTheNoticeToANewKey: the Commission changed its key
// after the notice; a pivot signed with the announced key names the new
// one, which signs the list. A pivot signed with an unknown key breaks the
// chain, and a list that no longer names the notice is refused.
func TestPivotListsLeadFromTheNoticeToANewKey(t *testing.T) {
	announced, next, newest := trustlist.NewOperator(t, "Announced"), trustlist.NewOperator(t, "Next"), trustlist.NewOperator(t, "Newest")
	pivot1, pivot2 := "https://example.invalid/eu-lotl-pivot-1.xml", "https://example.invalid/eu-lotl-pivot-2.xml"
	// Newest first, as the list names them.
	announcements := []string{pivot2, pivot1, notice}
	served := lists{
		pivot1: trustlist.Sign(t, lotlText([]trustlist.Operator{next}, []string{pivot1, notice}), announced),
		pivot2: trustlist.Sign(t, lotlText([]trustlist.Operator{newest}, []string{pivot2, pivot1, notice}), next),
	}
	current := trustlist.Sign(t, lotlText([]trustlist.Operator{newest}, announcements), newest)
	if territories, err := syncer(&countedLOTL{content: current}, served, announced).Territories(); err != nil || len(territories) != 2 {
		t.Fatalf("through the pivots: %v %v", territories, err)
	}

	broken := lists{pivot1: served[pivot1], pivot2: trustlist.Sign(t, lotlText([]trustlist.Operator{newest}, announcements), newest)}
	if _, err := syncer(&countedLOTL{content: current}, broken, announced).Territories(); err == nil || !strings.Contains(err.Error(), pivot2) {
		t.Errorf("a pivot not signed with the key before it: %v", err)
	}

	forgotten := trustlist.Sign(t, lotlText([]trustlist.Operator{newest}, []string{pivot2, pivot1}), newest)
	if _, err := syncer(&countedLOTL{content: forgotten}, served, announced).Territories(); err == nil || !strings.Contains(err.Error(), "newer trebaruna") {
		t.Errorf("a list that no longer names the notice: %v", err)
	}
	if _, err := syncer(&countedLOTL{content: current}, served).Territories(); err == nil {
		t.Error("without anchors nothing is authenticated")
	}
}

// TestATerritoryCodeIsNeverAPath: a pointer whose code is not two capital
// letters is not a territory, and nothing is written outside the cache.
func TestATerritoryCodeIsNeverAPath(t *testing.T) {
	commission := trustlist.NewOperator(t, "Commission")
	directory := t.TempDir()
	cache := filepath.Join(directory, "cache")
	hostile := pointer("../../escaped", "https://example.invalid/escaped.xml", generic, commission.Base64())
	source := &countedLOTL{content: trustlist.Sign(t, lotlText([]trustlist.Operator{commission}, []string{notice}, hostile), commission)}
	sync := syncer(source, lists{"https://example.invalid/escaped.xml": trustlist.Sign(t, `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>`, commission)}, commission)
	sync.CacheDir, sync.QuarantineDir = cache, filepath.Join(cache, "rejected")

	territories, err := sync.Territories()
	if err != nil || slices.ContainsFunc(territories, func(code string) bool { return strings.Contains(code, ".") }) {
		t.Fatalf("territories %v %v", territories, err)
	}
	if _, err := sync.Execute("../../escaped"); err == nil {
		t.Error("a code that is a path was synced")
	}
	if _, err := os.Stat(filepath.Join(directory, "escaped.xml")); err == nil {
		t.Error("a file was written outside the cache")
	}
}
