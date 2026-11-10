package domain_test

import (
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

func TestTheDocumentDecidesWhichFormatsMakeSense(t *testing.T) {
	cases := map[string][]domain.SignatureFormat{
		"/tmp/contratto.PDF":    {domain.FormatPAdES, domain.FormatCAdES, domain.FormatCAdESDetached, domain.FormatASiCS},
		"/tmp/fattura.xml":      {domain.FormatXAdES, domain.FormatCAdES, domain.FormatCAdESDetached, domain.FormatASiCS},
		"/tmp/offerta.docx":     {domain.FormatOOXML, domain.FormatCAdES, domain.FormatCAdESDetached, domain.FormatASiCS},
		"/tmp/senza-estensio":   {domain.FormatCAdES, domain.FormatCAdESDetached, domain.FormatASiCS},
		"/tmp/atto.pdf.p7m":     {domain.FormatCosign, domain.FormatCountersign, domain.FormatCAdES},
		"/tmp/offerta.txt.p7s":  {domain.FormatCosign, domain.FormatCountersign},
		"/tmp/expediente.ASICE": {domain.FormatCosign, domain.FormatCountersign},
		"/tmp/plano.pdf.asics":  {domain.FormatCosign, domain.FormatCountersign},
		"/tmp/acta.txt.xsig":    {domain.FormatCountersign},
	}
	for path, want := range cases {
		got := domain.FormatsFor(path)
		if len(got) != len(want) {
			t.Errorf("FormatsFor(%q) = %v, want %v", path, got, want)
			continue
		}
		for index := range want {
			if got[index] != want[index] {
				t.Errorf("FormatsFor(%q) = %v, want %v", path, got, want)
			}
		}
	}
}

func TestOnlyPAdESPutsAMarkOnThePage(t *testing.T) {
	if !domain.FormatPAdES.HasVisibleSeal() || domain.FormatCAdES.HasVisibleSeal() || domain.FormatXAdES.HasVisibleSeal() || domain.FormatCAdESDetached.HasVisibleSeal() {
		t.Error("only PAdES carries a visible seal")
	}
}

func TestLevelsKnowWhatTheyNeed(t *testing.T) {
	cases := []struct {
		level      domain.SignatureLevel
		timestamp  bool
		revocation bool
	}{
		{domain.LevelBasic, false, false},
		{domain.LevelTimestamp, true, false},
		{domain.LevelLongTerm, true, true},
		{domain.LevelArchive, true, true},
	}
	for _, testCase := range cases {
		if testCase.level.NeedsTimestamp() != testCase.timestamp || testCase.level.NeedsRevocation() != testCase.revocation {
			t.Errorf("%s: timestamp=%v revocation=%v", testCase.level,
				testCase.level.NeedsTimestamp(), testCase.level.NeedsRevocation())
		}
	}
	if levels := domain.Levels(); len(levels) != 4 || levels[0] != domain.LevelBasic {
		t.Errorf("Levels() = %v, want the four, weakest first", levels)
	}
}

func TestEveryLevelAboveBasicNeedsAnAuthority(t *testing.T) {
	for _, level := range []domain.SignatureLevel{domain.LevelTimestamp, domain.LevelLongTerm, domain.LevelArchive} {
		intent := validIntent()
		intent.Level = level
		if err := intent.Validate(); err == nil {
			t.Errorf("level %s without a TSA was accepted", level)
		}
	}
}

func TestCertificateStanding(t *testing.T) {
	now := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	future := now.Add(400 * 24 * time.Hour)

	cases := []struct {
		name    string
		summary domain.CertificateSummary
		want    domain.CertificateStanding
	}{
		{"qualified", domain.CertificateSummary{NotAfter: future, Trusted: true, Qualified: true}, domain.StandingQualified},
		{"trusted", domain.CertificateSummary{NotAfter: future, Trusted: true}, domain.StandingTrusted},
		{"self-signed", domain.CertificateSummary{NotAfter: future, Trusted: true, SelfSigned: true}, domain.StandingUntrusted},
		{"unknown issuer", domain.CertificateSummary{NotAfter: future}, domain.StandingUntrusted},
		{"expired beats qualified", domain.CertificateSummary{NotAfter: now.Add(-time.Hour), Qualified: true}, domain.StandingExpired},
	}
	for _, testCase := range cases {
		if got := testCase.summary.Standing(now); got != testCase.want {
			t.Errorf("%s: standing = %s, want %s", testCase.name, got, testCase.want)
		}
	}
}

func TestAnApproachingExpiryIsWorthMentioning(t *testing.T) {
	now := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

	soon := domain.CertificateSummary{NotAfter: now.Add(12*24*time.Hour + time.Hour)}
	if !soon.ExpiresSoon(now) || soon.DaysLeft(now) != 12 {
		t.Errorf("12 days left: soon=%v days=%d", soon.ExpiresSoon(now), soon.DaysLeft(now))
	}
	later := domain.CertificateSummary{NotAfter: now.Add(90 * 24 * time.Hour)}
	if later.ExpiresSoon(now) {
		t.Error("90 days left is not soon")
	}
	gone := domain.CertificateSummary{NotAfter: now.Add(-time.Hour)}
	if gone.ExpiresSoon(now) || gone.DaysLeft(now) != 0 {
		t.Error("an expired certificate is expired, not expiring")
	}
}

func TestABatchResolvesItsFormatPerDocument(t *testing.T) {
	if formats := domain.BatchFormats(); len(formats) != 4 || formats[0] != domain.FormatEach || formats[3] != domain.FormatASiCE {
		t.Fatalf("BatchFormats = %v", formats)
	}
	cases := map[string]domain.SignatureFormat{
		"/tmp/a.pdf": domain.FormatPAdES, "/tmp/b.xml": domain.FormatXAdES, "/tmp/c.docx": domain.FormatOOXML,
		"/tmp/d.txt": domain.FormatCAdES,
	}
	for path, want := range cases {
		if got := domain.FormatEach.For(path); got != want {
			t.Errorf("each.For(%s) = %s, want %s", path, got, want)
		}
		if got := domain.FormatCAdESDetached.For(path); got != domain.FormatCAdESDetached {
			t.Errorf("a forced format stays as it is, got %s", got)
		}
	}
}

// TestEachFormatDeclaresThePoliciesItCanCarry: AGE 1.9 in a PDF, both AGE
// versions in CMS and XML, FacturaE's for an invoice, none in containers
// or office documents; an invoice needs its policy and a known role.
func TestEachFormatDeclaresThePoliciesItCanCarry(t *testing.T) {
	cases := map[domain.SignatureFormat][]domain.PolicyName{
		domain.FormatPAdES:    {domain.PolicyNone, domain.PolicyAGE},
		domain.FormatXAdES:    {domain.PolicyNone, domain.PolicyAGE, domain.PolicyAGE18},
		domain.FormatFacturaE: {domain.PolicyFacturaE, domain.PolicyFacturaE30},
		domain.FormatASiCS:    nil,
		domain.FormatOOXML:    nil,
	}
	for format, want := range cases {
		if got := format.Policies(); len(got) != len(want) || (len(want) > 0 && got[len(got)-1] != want[len(want)-1]) {
			t.Errorf("%s: %v, want %v", format, got, want)
		}
	}
	base := domain.SigningIntent{DocumentPath: "/tmp/a.pdf", Key: domain.CertificateFile{Path: "/tmp/k.p12"}, Format: domain.FormatPAdES,
		Level: domain.LevelBasic, Seal: domain.SealChoice{Page: 1}}
	for name, test := range map[string]struct {
		change func(*domain.SigningIntent)
		code   domain.ProblemCode
	}{
		"AGE 1.8 in a PDF":    {func(i *domain.SigningIntent) { i.Policy = domain.PolicyAGE18 }, domain.ProblemPolicyFormat},
		"a policy in ASiC":    {func(i *domain.SigningIntent) { i.Format, i.Policy = domain.FormatASiCS, domain.PolicyAGE }, domain.ProblemPolicyFormat},
		"an invoice, no role": {func(i *domain.SigningIntent) { i.Format, i.Policy = domain.FormatFacturaE, domain.PolicyFacturaE }, domain.ProblemInvoiceRole},
		"an invoice, a guess": {func(i *domain.SigningIntent) {
			i.Format, i.Policy, i.Role = domain.FormatFacturaE, domain.PolicyFacturaE, "jefe"
		}, domain.ProblemInvoiceRole},
		"an invoice, no policy": {func(i *domain.SigningIntent) { i.Format, i.Role = domain.FormatFacturaE, "emisor" }, domain.ProblemInvoiceRole},
	} {
		intent := base
		test.change(&intent)
		if problem, ok := intent.Validate().(domain.Problem); !ok || problem.Code != test.code {
			t.Errorf("%s: %v", name, intent.Validate())
		}
	}
	valid := base
	valid.Format, valid.Policy, valid.Role = domain.FormatFacturaE, domain.PolicyFacturaE, "tercero"
	if err := valid.Validate(); err != nil {
		t.Errorf("an invoice signed by a third party: %v", err)
	}
	if invoice := domain.InvoiceFormats(); invoice[0] != domain.FormatFacturaE {
		t.Errorf("an invoice is offered as one first: %v", invoice)
	}
}
