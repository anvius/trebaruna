package domain

import "time"

// QualifiedServicesFor returns the granted qualified CAs whose certificate
// subject matches an issuer distinguished name.
//
// The TSL publishes the CA certificates, and a leaf is signed by one of them, so
// comparing subjects is the same test Go's chain builder applies. A name match
// is necessary but not sufficient: the caller still has to check the certificate
// claims and the moment the service was granted.
func (l TrustList) QualifiedServicesFor(issuerDN string) []TrustService {
	if issuerDN == "" {
		return nil
	}

	var matched []TrustService
	for _, service := range l.Services {
		if !service.CanIssueQualifiedSignature() {
			continue
		}
		for _, listed := range service.Certificates {
			if listed.Subject.String() == issuerDN {
				matched = append(matched, service)
				break
			}
		}
	}
	return matched
}

// GrantNotice is where a service's current status took effect.
//
// Exposed as a method so callers do not have to know that an unset date means
// "the list does not say", which is different from "granted long ago".
func (s TrustService) GrantNotice() (time.Time, bool) {
	if s.StatusSince.IsZero() {
		return time.Time{}, false
	}
	return s.StatusSince, true
}
