package parser_test

// The parser is verified against a hand-written list that reproduces the exact
// shape of the real ones (scheme info, provider, service, X509Certificate), so
// the test runs offline and still exercises the streaming path.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/trust/infrastructure"
)

const sampleList = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeTerritory>IT</SchemeTerritory>
    <SchemeOperatorName><Name xml:lang="en">Agenzia per l'Italia Digitale</Name></SchemeOperatorName>
    <IssueDateTime>2026-09-24T00:00:00Z</IssueDateTime>
    <NextUpdate>2027-03-24T00:00:00Z</NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">ExampleTSP S.p.A.</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Example Qualified CA</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>CERTIFICATE_ONE</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Example Qualified TSA</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
          </ServiceInformation>
        </TSPService>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Withdrawn CA</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

func TestParserReadsSchemeInformation(t *testing.T) {
	list, err := infrastructure.TSLParser{}.Parse(strings.NewReader(sampleList))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if list.Territory != "IT" {
		t.Errorf("territory = %q, want IT", list.Territory)
	}
	if list.NextUpdate.Year() != 2027 {
		t.Errorf("next update = %v, want 2027", list.NextUpdate)
	}
	if list.PublishedAt.Year() != 2026 {
		t.Errorf("published = %v, want 2026", list.PublishedAt)
	}
}

func TestParserCountsServicesAndQualification(t *testing.T) {
	list, err := infrastructure.TSLParser{}.Parse(strings.NewReader(sampleList))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(list.Services) != 3 {
		t.Fatalf("services = %d, want 3", len(list.Services))
	}
	// Only the granted CA/QC can *issue* qualified signatures. A TSA seals
	// timestamps, it does not sign documents, so it must not be counted here.
	if list.QualifiedCount() != 1 {
		t.Errorf("qualified signers = %d, want 1 (the granted CA/QC)", list.QualifiedCount())
	}
	// All three services are listed as qualified, withdrawn included.
	listed := 0
	for _, service := range list.Services {
		if service.Qualified {
			listed++
		}
	}
	if listed != 3 {
		t.Errorf("qualified listings = %d, want 3", listed)
	}
	if list.ActiveCount() != 2 {
		t.Errorf("granted services = %d, want 2", list.ActiveCount())
	}

	// CA/QC keeps its full type: taking only the last path segment turns it into
	// "QC" and silently unqualifies every CA in every list.
	if list.Services[0].ServiceType != "CA/QC" {
		t.Errorf("service type = %q, want CA/QC", list.Services[0].ServiceType)
	}
	if !list.Services[0].CanIssueQualifiedSignature() {
		t.Error("a granted CA/QC must be able to issue qualified signatures")
	}
}

func TestWithdrawnServiceIsNotQualifiedForNewSignatures(t *testing.T) {
	list, err := infrastructure.TSLParser{}.Parse(strings.NewReader(sampleList))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	withdrawn := list.Services[2]
	if withdrawn.Status != "withdrawn" {
		t.Errorf("status = %q, want withdrawn", withdrawn.Status)
	}
	if withdrawn.CanIssueQualifiedSignature() {
		t.Error("a withdrawn CA must not be offered for new signatures")
	}
}

func TestParserReadsProviderName(t *testing.T) {
	list, err := infrastructure.TSLParser{}.Parse(strings.NewReader(sampleList))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if list.Services[0].ProviderName != "ExampleTSP S.p.A." {
		t.Errorf("provider = %q", list.Services[0].ProviderName)
	}
}

func TestParserDecodesCertificates(t *testing.T) {
	certificate := buildCertificate(t)
	encoded := base64.StdEncoding.EncodeToString(certificate.Raw)

	list, err := infrastructure.TSLParser{}.Parse(
		strings.NewReader(strings.Replace(sampleList, "CERTIFICATE_ONE", encoded, 1)),
	)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(list.Services[0].Certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(list.Services[0].Certificates))
	}
	if list.Services[0].Certificates[0].Subject.CommonName != "Test CA" {
		t.Errorf("certificate CN = %q", list.Services[0].Certificates[0].Subject.CommonName)
	}
}

func TestParserRejectsMalformedXML(t *testing.T) {
	if _, err := (infrastructure.TSLParser{}).Parse(strings.NewReader("<not-xml")); err == nil {
		t.Fatal("malformed XML must be reported")
	}
}

func TestListFreshness(t *testing.T) {
	list := infrastructure.MustParseForTest(sampleList, t)

	if !list.Fresh(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("the list is fresh before NextUpdate")
	}
	if list.Fresh(time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("the list is stale after NextUpdate")
	}
}

// buildCertificate makes a throwaway CA certificate.
func buildCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA", Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}

// TestABrainpoolAuthorityIsReadFromTheList: the German list publishes the
// health professionals' authorities, whose keys are on brainpool curves;
// they become anchors like any other.
func TestABrainpoolAuthorityIsReadFromTheList(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	for _, arguments := range [][]string{
		{"ecparam", "-name", "brainpoolP256r1", "-genkey", "-noout", "-out", "ca.key"},
		{"req", "-x509", "-new", "-key", "ca.key", "-subj", "/C=DE/O=Aerztekammer/CN=HBA-CA 7", "-days", "30", "-outform", "DER", "-out", "ca.der"},
	} {
		command := exec.Command("openssl", arguments...)
		command.Dir = directory
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", arguments, err, output)
		}
	}
	der, _ := os.ReadFile(filepath.Join(directory, "ca.der"))
	list, err := infrastructure.TSLParser{}.Parse(strings.NewReader(strings.Replace(sampleList, "CERTIFICATE_ONE", base64.StdEncoding.EncodeToString(der), 1)))
	if err != nil {
		t.Fatal(err)
	}
	certificates := list.Services[0].Certificates
	if len(certificates) != 1 || certificates[0].Subject.CommonName != "HBA-CA 7" {
		t.Fatalf("the authority is not read: %d certificates", len(certificates))
	}
	if _, ok := certificates[0].PublicKey.(*brainpool.PublicKey); !ok {
		t.Errorf("its key is %T", certificates[0].PublicKey)
	}
}
