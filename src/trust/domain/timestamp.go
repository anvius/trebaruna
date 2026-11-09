package domain

import (
	"crypto/x509"
	"time"
)

// TimestampAuthority is the verdict on the authority that sealed a signature.
//
// A timestamp answers "when", but only if the authority behind it is real. The
// token's own signature proves the seal is intact; the trust list proves the
// sealer is a qualified time-stamping authority. Neither alone is enough, which
// is why the report separates "bound" from "accredited".
type TimestampAuthority struct {
	// ServiceListed reports a granted TSA/QTST in an authenticated list that can
	// issue the timestamp certificate's chain.
	ServiceListed bool
	// ProviderName and ServiceName identify the matched service.
	ProviderName string
	ServiceName  string
	// GrantedSince is when the service entered its current status.
	GrantedSince time.Time
	// CertificateQualified reports the extended key usage a qualified timestamp
	// certificate must carry (id-kp-timeStamping, critical).
	CertificateQualified bool
	// Reason explains the verdict in English.
	Reason string
}

// Accredited reports whether the timestamp authority is proven qualified at the
// moment the token claims.
//
// The token's own time is the reference: a service granted after the seal was
// made cannot have issued it. When the list publishes no date the comparison is
// skipped, because there is nothing to contradict.
func (t TimestampAuthority) Accredited(at time.Time) bool {
	if !t.ServiceListed || !t.CertificateQualified {
		return false
	}
	if !t.GrantedSince.IsZero() {
		if at.IsZero() || at.Before(t.GrantedSince) {
			return false
		}
	}
	return true
}

// Missing lists the conditions that keep a timestamp from being accredited.
func (t TimestampAuthority) Missing(at time.Time) []string {
	var missing []string
	if !t.CertificateQualified {
		missing = append(missing, "the timestamp certificate does not carry the timeStamping key usage")
	}
	if !t.ServiceListed {
		missing = append(missing, "no granted TSA/QTST in the authenticated trust list issued this timestamp")
	}
	if !t.GrantedSince.IsZero() {
		switch {
		case at.IsZero():
			missing = append(missing, "the timestamp time is unknown, so the authority grant cannot be checked")
		case at.Before(t.GrantedSince):
			missing = append(missing, "the timestamp authority was not granted yet when the token was issued")
		}
	}
	return missing
}

// QualifiedTimestampService finds the granted qualified time-stamping service
// that covers a timestamping unit's certificate: the exact certificate first,
// then its issuer.
//
// The order is measured, not stylistic: across the 18 authenticated lists,
// 227 of 231 granted TSA/QTST services publish the unit's own certificate while
// only 60 can be reached through their issuer.
func (l TrustList) QualifiedTimestampService(certificate *x509.Certificate) (TrustService, bool) {
	if certificate == nil {
		return TrustService{}, false
	}
	if services := l.TimestampServiceForCertificate(certificate); len(services) > 0 {
		return services[0], true
	}
	if services := l.TimestampServicesFor(certificate.Issuer.String()); len(services) > 0 {
		return services[0], true
	}
	return TrustService{}, false
}

// TimestampServicesFor returns the granted qualified time-stamping services that
// could have issued a certificate whose issuer is the given distinguished name.
//
// Some states publish the authority's CA, others publish the end-entity
// certificate of the time-stamping unit itself. Matching the issuer covers the
// first; the caller also matches the leaf's subject, which covers the second.
func (l TrustList) TimestampServicesFor(issuerDN string) []TrustService {
	return l.timestampServicesMatching(func(listed *x509.Certificate) bool {
		return listed.Subject.String() == issuerDN
	})
}

// TimestampServiceForCertificate returns the service that published exactly this
// certificate, for lists that list the end-entity instead of its issuer.
func (l TrustList) TimestampServiceForCertificate(certificate *x509.Certificate) []TrustService {
	if certificate == nil {
		return nil
	}
	return l.timestampServicesMatching(func(listed *x509.Certificate) bool {
		return listed.Equal(certificate)
	})
}

// timestampServicesMatching is the shared scan.
func (l TrustList) timestampServicesMatching(matches func(*x509.Certificate) bool) []TrustService {
	var found []TrustService
	for _, service := range l.Services {
		if !service.CanTimestamp() {
			continue
		}
		for _, listed := range service.Certificates {
			if matches(listed) {
				found = append(found, service)
				break
			}
		}
	}
	return found
}
