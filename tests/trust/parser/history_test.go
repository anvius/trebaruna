package parser_test

// Regression tests for the streaming parser. Each one pins a bug that was
// measured against the live Italian list, not a hypothetical: a trust list whose
// statuses are wrong hands out trust anchors to withdrawn authorities.

import (
	"crypto/x509"
	"strings"
	"testing"

	"codeberg.org/anvius/trebaruna/src/trust/domain"
	"codeberg.org/anvius/trebaruna/src/trust/infrastructure"
)

// listWithHistory reproduces the real shape: the current entry comes first, then
// a ServiceHistory subtree repeating older statuses, names and certificates.
const listWithHistory = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeTerritory>IT</SchemeTerritory>
    <IssueDateTime>2026-09-24T00:00:00Z</IssueDateTime>
    <NextUpdate>2027-03-24T00:00:00Z</NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Example Provider</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Example Qualified CA</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2019-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
          <ServiceHistory>
            <ServiceHistoryInstance>
              <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
              <ServiceName><Name xml:lang="en">Example Qualified CA (old name)</Name></ServiceName>
              <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited</ServiceStatus>
              <StatusStartingTime>2008-02-25T16:42:03Z</StatusStartingTime>
            </ServiceHistoryInstance>
          </ServiceHistory>
        </TSPService>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Retired CA</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
            <StatusStartingTime>2021-05-05T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
          <ServiceHistory>
            <ServiceHistoryInstance>
              <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
              <ServiceName><Name xml:lang="en">Retired CA (was granted)</Name></ServiceName>
              <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
              <StatusStartingTime>2012-01-01T00:00:00Z</StatusStartingTime>
            </ServiceHistoryInstance>
          </ServiceHistory>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

// TestHistoryDoesNotOverwriteCurrentStatus is the most important test in this
// file. Before the fix, 307 of 562 Italian services carried a status taken from
// their own history, which turned 11 withdrawn CAs into granted ones.
func TestHistoryDoesNotOverwriteCurrentStatus(t *testing.T) {
	list, err := infrastructure.TSLParser{}.Parse(strings.NewReader(listWithHistory))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(list.Services) != 2 {
		t.Fatalf("services = %d, want 2", len(list.Services))
	}
	if got := list.Services[0].Status; got != domain.StatusGranted {
		t.Errorf("current status = %q, want granted: history must not overwrite it", got)
	}
	if got := list.Services[1].Status; got != domain.StatusWithdrawn {
		t.Errorf("current status = %q, want withdrawn: a historical \"granted\" is not current", got)
	}
}

// TestWithdrawnServiceIsNotAnAnchor is the consequence of the bug above: an
// anchor is a promise that its holder speaks for a supervised authority.
func TestWithdrawnServiceIsNotAnAnchor(t *testing.T) {
	list, err := infrastructure.TSLParser{}.Parse(strings.NewReader(listWithHistory))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if list.Services[1].CanIssueQualifiedSignature() {
		t.Error("a withdrawn CA must not be able to issue qualified signatures")
	}
	if list.QualifiedCount() != 1 {
		t.Errorf("qualified = %d, want 1 (the granted CA only)", list.QualifiedCount())
	}
}

// TestServicesOfOneProviderDoNotShareState: reusing the struct across services
// leaked the first service's name, status and qualifiers into the rest. 498 of
// 562 service names in the Italian list were wrong.
func TestServicesOfOneProviderDoNotShareState(t *testing.T) {
	list, err := infrastructure.TSLParser{}.Parse(strings.NewReader(listWithHistory))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got := list.Services[0].ServiceName; got != "Example Qualified CA" {
		t.Errorf("service name = %q, want the current one without history", got)
	}
	if got := list.Services[1].ServiceName; got != "Retired CA" {
		t.Errorf("service name = %q, leaked from the previous service", got)
	}
	if list.Services[0].ProviderName != "Example Provider" || list.Services[1].ProviderName != "Example Provider" {
		t.Error("both services belong to the same provider and must keep its name")
	}
	if list.Services[1].StatusSince.Year() != 2021 {
		t.Errorf("status since = %v, want 2021: the current date, not the historical one", list.Services[1].StatusSince)
	}
}

// TestQualifiersAreReadFromTheURIAttribute: the Qualifier element is empty and
// carries its value in the uri attribute. Reading text yields nothing, which
// silently disables the QSCD half of the QES check.
func TestQualifiersAreReadFromTheURIAttribute(t *testing.T) {
	const withQualifiers = `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><SchemeTerritory>BE</SchemeTerritory></SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation><TSPName><Name xml:lang="en">Provider</Name></TSPName></TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceInformationExtensions>
              <Extension Critical="true">
                <ns5:Qualifications xmlns:ns5="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#">
                  <ns5:QualificationElement>
                    <ns5:Qualifiers>
                      <ns5:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"/>
                    </ns5:Qualifiers>
                  </ns5:QualificationElement>
                </ns5:Qualifications>
              </Extension>
            </ServiceInformationExtensions>
          </ServiceInformation>
        </TSPService>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

	list, err := infrastructure.TSLParser{}.Parse(strings.NewReader(withQualifiers))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !list.Services[0].HasQualifier("QCWithQSCD") {
		t.Errorf("qualifiers = %v, want QCWithQSCD", list.Services[0].Qualifiers)
	}
	if len(list.Services[1].Qualifiers) != 0 {
		t.Errorf("qualifiers = %v, want none: they must not leak between services", list.Services[1].Qualifiers)
	}
}

// TestQualifiedServicesMatchOnTheExactIssuer: matching by display name would
// attribute a certificate to a provider that merely shares a brand.
func TestQualifiedServicesMatchOnTheExactIssuer(t *testing.T) {
	ca := buildCertificate(t)
	list := domain.TrustList{
		Services: []domain.TrustService{{
			ProviderName: "Example Provider",
			ServiceType:  "CA/QC",
			Status:       domain.StatusGranted,
			Qualified:    true,
			Certificates: []*x509.Certificate{ca},
		}},
	}

	matched := list.QualifiedServicesFor(ca.Subject.String())
	if len(matched) != 1 {
		t.Fatalf("matched = %d services, want 1 by exact subject", len(matched))
	}

	// The issuer of an end-entity certificate is the CA subject, so the leaf's
	// issuer must be what the lookup accepts, and a look-alike name must not.
	if got := list.QualifiedServicesFor(ca.Subject.CommonName); len(got) != 0 {
		t.Errorf("a common name alone must not match: got %d services", len(got))
	}
	if got := list.QualifiedServicesFor(""); len(got) != 0 {
		t.Error("an empty issuer cannot match anything")
	}
}

// TestWithdrawnServicesAreNeverMatched: an issuer that stopped operating must
// not be offered as the authority behind a current signature.
func TestWithdrawnServicesAreNeverMatched(t *testing.T) {
	ca := buildCertificate(t)
	list := domain.TrustList{
		Services: []domain.TrustService{{
			ProviderName: "Example Provider",
			ServiceType:  "CA/QC",
			Status:       domain.StatusWithdrawn,
			Qualified:    true,
			Certificates: []*x509.Certificate{ca},
		}},
	}

	if matched := list.QualifiedServicesFor(ca.Subject.String()); len(matched) != 0 {
		t.Errorf("matched = %d, want 0: a withdrawn CA issues nothing now", len(matched))
	}
}
