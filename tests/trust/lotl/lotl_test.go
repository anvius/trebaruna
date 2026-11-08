package lotl_test

// Trust list authentication: the chain that turns a downloaded file into a
// trusted anchor. Without it, "emitido por una CA cualificada" is a claim.

import (
	"strings"
	"testing"

	trustdomain "codeberg.org/simplicer/trebaruna/src/trust/domain"
	trustinfra "codeberg.org/simplicer/trebaruna/src/trust/infrastructure"
)

const sampleLOTL = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <IssueDateTime>2026-10-15T00:00:00Z</IssueDateTime>
    <NextUpdate>2027-04-15T00:00:00Z</NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/ELSigning</ServiceTypeIdentifier>
            <OtherTSLPointer>
              <ServiceDigitalIdentities>
                <ServiceDigitalIdentity>
                  <DigitalId><X509Certificate>MIIBkTCB+wIJAJ8Z</X509Certificate></DigitalId>
                </ServiceDigitalIdentity>
              </ServiceDigitalIdentities>
              <TSLLocation>https://example.invalid/TSL-XX.xml</TSLLocation>
              <AdditionalInformation>
                <OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType></OtherInformation>
                <OtherInformation><SchemeTerritory>XX</SchemeTerritory></OtherInformation>
                <OtherInformation><ns3:MimeType>application/vnd.etsi.tsl+xml</ns3:MimeType></OtherInformation>
              </AdditionalInformation>
            </OtherTSLPointer>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

// TestLOTLParserReadsTerritoriesAndCertificates covers the LOTL shape, which
// differs from a national TSL: the pointers live under OtherTSLPointer.
func TestLOTLParserReadsTerritoriesAndCertificates(t *testing.T) {
	lotl, err := trustinfra.LOTLParser{}.Parse(strings.NewReader(sampleLOTL))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(lotl.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(lotl.Entries))
	}

	entry := lotl.Entries[0]
	if entry.Territory != "XX" {
		t.Errorf("territory = %q", entry.Territory)
	}
	if !strings.HasSuffix(entry.Location, "TSL-XX.xml") {
		t.Errorf("location = %q", entry.Location)
	}
	if !entry.XML() {
		t.Error("an .xml location must be treated as XML")
	}
	if entry.CanSign() {
		t.Error("this fixture carries an unparsable certificate, so it cannot sign")
	}
}

// TestLOTLFindIsCaseInsensitive keeps `--territory it` working.
func TestLOTLFindIsCaseInsensitive(t *testing.T) {
	lotl, err := trustinfra.LOTLParser{}.Parse(strings.NewReader(sampleLOTL))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if _, found := lotl.Find("xx"); !found {
		t.Error("a lower-case territory must be found")
	}
	if _, found := lotl.Find("ZZ"); found {
		t.Error("an unknown territory must not be found")
	}
}

// TestLOTLRejectsEmptyList keeps a captive-portal response from looking valid.
func TestLOTLRejectsEmptyList(t *testing.T) {
	if _, err := (trustinfra.LOTLParser{}).Parse(strings.NewReader("<html></html>")); err == nil {
		t.Fatal("a document with no territory entries must be rejected")
	}
}

// TestPDFOnlyTerritoriesCannotSign is the honest limit: four EU states publish
// only a PDF, which cannot be parsed or authenticated, so they stay inventory.
func TestPDFOnlyTerritoriesCannotSign(t *testing.T) {
	xmlEntry := trustdomain.LOTLEntry{
		Territory: "IT",
		Location:  "https://example.invalid/TSL-IT.xml",
		MimeType:  "application/vnd.etsi.tsl+xml",
	}
	if !xmlEntry.XML() {
		t.Error("an XML entry must be recognised")
	}

	pdfEntry := trustdomain.LOTLEntry{
		Territory: "ES",
		Location:  "https://example.invalid/TSL-ES.pdf",
		MimeType:  "application/pdf",
	}
	if pdfEntry.XML() {
		t.Error("a PDF entry must not be treated as XML")
	}
}
