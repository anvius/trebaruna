package domain

import "time"

// CertificateFile is a certificate with its private key on disk, and the
// passphrase that opens it.
type CertificateFile struct {
	Path       string
	Passphrase string
}

// CertificateSummary is what the window shows about the chosen certificate,
// read from the certificate itself so the user never types it.
type CertificateSummary struct {
	Holder     string
	Identifier string
	Issuer     string
	NotAfter   time.Time
	SelfSigned bool
	Trusted    bool
	Qualified  bool
	// Locality is where the certificate says its holder is, when it says so.
	Locality string
}

// CertificateStanding is the one fact a user needs before signing.
type CertificateStanding string

const (
	// StandingQualified means a qualified certificate on a trusted list.
	StandingQualified CertificateStanding = "qualified"

	// StandingTrusted means an issuer on a trusted list, not qualified.
	StandingTrusted CertificateStanding = "trusted"

	// StandingUntrusted means no trusted list vouches for the issuer.
	StandingUntrusted CertificateStanding = "untrusted"

	// StandingExpired means the certificate can no longer sign.
	StandingExpired CertificateStanding = "expired"
)

// expiryWarning is how far ahead an approaching expiry is worth mentioning.
const expiryWarning = 30 * 24 * time.Hour

// Standing ranks what matters most: an expired certificate is expired,
// however trusted its issuer.
func (c CertificateSummary) Standing(now time.Time) CertificateStanding {
	switch {
	case now.After(c.NotAfter):
		return StandingExpired
	case c.Qualified:
		return StandingQualified
	case c.Trusted && !c.SelfSigned:
		return StandingTrusted
	}
	return StandingUntrusted
}

// ExpiresSoon reports an expiry within the warning window.
func (c CertificateSummary) ExpiresSoon(now time.Time) bool {
	return !now.After(c.NotAfter) && c.NotAfter.Sub(now) < expiryWarning
}

// DaysLeft is the number of whole days before expiry, never negative.
func (c CertificateSummary) DaysLeft(now time.Time) int {
	if now.After(c.NotAfter) {
		return 0
	}
	return int(c.NotAfter.Sub(now).Hours() / 24)
}
