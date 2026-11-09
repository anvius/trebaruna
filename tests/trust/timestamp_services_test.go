package trust_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	trust "codeberg.org/simplicer/trebaruna/src/trust/domain"
	"codeberg.org/simplicer/trebaruna/src/trust/infrastructure"
)

// TestEveryQualifiedTimestampUnitIsRecognised runs against real trusted lists
// downloaded with `trebaruna trust sync` (TREBARUNA_TSL_DIR=<cache>/trebaruna/tsl):
// the certificate of every granted TSA/QTST service must be recognised as
// qualified, and no CA/QC certificate may be.
func TestEveryQualifiedTimestampUnitIsRecognised(t *testing.T) {
	directory := os.Getenv("TREBARUNA_TSL_DIR")
	if directory == "" {
		t.Skip("set TREBARUNA_TSL_DIR to a directory of downloaded trusted lists")
	}
	files, _ := filepath.Glob(filepath.Join(directory, "*.xml"))
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		list, err := infrastructure.TSLParser{}.Parse(file)
		file.Close()
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		recognised, units := 0, 0
		for _, service := range list.Services {
			for _, certificate := range service.Certificates {
				_, found := list.QualifiedTimestampService(certificate)
				switch {
				case service.CanTimestamp():
					units++
					if found {
						recognised++
					}
				case service.ServiceType == "CA/QC" && found && !hasTimestampUnit(list, certificate):
					t.Errorf("%s: the CA/QC certificate %s is taken for a timestamp unit", list.Territory, certificate.Subject)
				}
			}
		}
		if units > 0 && recognised != units {
			t.Errorf("%s: %d of %d qualified timestamp certificates recognised", list.Territory, recognised, units)
		}
		t.Logf("%s: %d qualified timestamp certificates, %d services listed by TimestampAuthorities",
			list.Territory, units, len(list.TimestampAuthorities()))
	}
}

// hasTimestampUnit reports a certificate the list also publishes under a QTST
// service (some providers list the same CA for both).
func hasTimestampUnit(list trust.TrustList, certificate *x509.Certificate) bool {
	return len(list.TimestampServiceForCertificate(certificate)) > 0
}

// TestAQualifiedTimestampServiceIsFoundByItsCertificateOrIssuer, on a list
// built here.
func TestAQualifiedTimestampServiceIsFoundByItsCertificateOrIssuer(t *testing.T) {
	unit := &x509.Certificate{Raw: []byte{1}, RawSubject: []byte{2}}
	withdrawn := trust.TrustService{ProviderName: "Old", ServiceType: "TSA/QTST", Qualified: true, Status: trust.StatusWithdrawn,
		Certificates: []*x509.Certificate{unit}}
	list := trust.TrustList{Services: []trust.TrustService{withdrawn}}
	if _, found := list.QualifiedTimestampService(unit); found {
		t.Error("a withdrawn service qualifies nothing")
	}
	granted := withdrawn
	granted.ProviderName, granted.Status, granted.StatusSince = "Actalis S.p.A.", trust.StatusGranted, time.Now().Add(-time.Hour)
	list.Services = append(list.Services, granted)
	if service, found := list.QualifiedTimestampService(unit); !found || service.ProviderName != "Actalis S.p.A." {
		t.Errorf("found %v, %+v", found, service)
	}
	if _, found := list.QualifiedTimestampService(nil); found {
		t.Error("no certificate, no service")
	}
	if authorities := list.TimestampAuthorities(); len(authorities) != 1 || authorities[0].Provider != "Actalis S.p.A." {
		t.Errorf("authorities %+v", authorities)
	}
}
