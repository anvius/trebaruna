package domain_test

import (
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

func TestTheDocumentDecidesWhichFormatsMakeSense(t *testing.T) {
	cases := map[string][]domain.SignatureFormat{
		"/tmp/contratto.PDF":  {domain.FormatPAdES, domain.FormatCAdES},
		"/tmp/fattura.xml":    {domain.FormatXAdES, domain.FormatCAdES},
		"/tmp/offerta.docx":   {domain.FormatCAdES},
		"/tmp/senza-estensio": {domain.FormatCAdES},
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
	if !domain.FormatPAdES.HasVisibleSeal() || domain.FormatCAdES.HasVisibleSeal() || domain.FormatXAdES.HasVisibleSeal() {
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
