// Package domain models trust lists (TSL) and certificate verdicts.
//
// A verification tool has to answer "is this issuer one we recognise?" and the
// only defensible source is the official EU trust list, not a bundled guess.
// The domain keeps the list as data; fetching and parsing live in infrastructure.
package domain

import (
	"crypto/x509"
	"time"
)

// TrustService is one qualified service listed in a national TSL.
type TrustService struct {
	// ProviderName is the trust service provider, e.g. "ArubaPEC S.p.A.".
	ProviderName string
	// ServiceName is the specific service.
	ServiceName string
	// ServiceType follows the EU types: CA/QC for qualified certificates,
	// AdESig/AdESeal for qualified electronic signatures and seals, TS for
	// timestamps.
	ServiceType string
	// Status is granted, withdrawn or deprecated as published.
	Status string
	// Qualified reports whether the service is listed as qualified.
	Qualified bool
	// Certificates are the service's certificates, when the TSL publishes them.
	Certificates []*x509.Certificate
}

// Qualified reports whether this service can issue qualified signatures.
func (s TrustService) CanIssueQualifiedSignature() bool {
	if !s.Qualified || s.Status != "granted" {
		return false
	}
	switch s.ServiceType {
	case "CA/QC", "AdESig", "AdESigQC":
		return true
	}
	return false
}

// TrustList is a national trusted list.
type TrustList struct {
	// Territory is the ISO code, e.g. "IT" or "ES".
	Territory string
	// SchemeName is the list's human name.
	SchemeName string
	// PublishedAt and NextUpdate come from the list itself: an out-of-date list
	// makes every verdict unreliable, so they are kept.
	PublishedAt time.Time
	NextUpdate  time.Time
	// Services is every listed service.
	Services []TrustService
	// Source records where the list came from, for the report.
	Source string
}

// Provider is the answer about one certificate's issuer.
type Provider string

const (
	// ProviderQualified means the issuer is listed as a qualified provider.
	ProviderQualified Provider = "qualified"

	// ProviderPublic is a certificate from the public web PKI: trusted for TLS
	// but not necessarily for qualified signatures.
	ProviderPublic Provider = "public"

	// ProviderSelfSigned means the certificate signed itself.
	ProviderSelfSigned Provider = "self-signed"

	// ProviderUnknown means no authority recognises the issuer.
	ProviderUnknown Provider = "unknown"
)

// LRU of verdicts is unnecessary; the pool lookup is already cheap.

// IssuerVerdict describes what we know about a certificate's provenance.
type IssuerVerdict struct {
	Provider Provider
	// Trusted reports whether the chain validates against a trusted root.
	Trusted bool
	// Qualified reports whether the issuer appears as a qualified provider.
	Qualified bool
	// Reason explains the verdict for the report.
	Reason string
	// VerifyError keeps the underlying error, if any.
	VerifyError error
}

// EvaluateIssuer classifies a certificate against the pools and the trust list.
//
// Order matters: a self-signed certificate must be reported as such even when
// the system pool happens to contain a same-named root, and a qualified provider
// outranks a plain public one.
func EvaluateIssuer(certificate *x509.Certificate, roots *x509.CertPool, list TrustList) IssuerVerdict {
	if certificate == nil {
		return IssuerVerdict{Provider: ProviderUnknown, Reason: "no certificate"}
	}

	if isSelfSigned(certificate) {
		return IssuerVerdict{
			Provider: ProviderSelfSigned,
			Reason:   "the certificate is its own issuer",
		}
	}

	if list.Qualified(certificate) {
		return IssuerVerdict{
			Provider:  ProviderQualified,
			Trusted:   true,
			Qualified: true,
			Reason:    "the issuer is a qualified provider in the " + list.Territory + " trusted list",
		}
	}

	if roots == nil {
		return IssuerVerdict{
			Provider: ProviderUnknown,
			Reason:   "no trusted roots available to validate the chain",
		}
	}

	intermediates := x509.NewCertPool()
	// The signing certificate's own chain may travel with the document; putting
	// the leaf in the intermediate pool is harmless and lets Go build the path.
	intermediates.AddCert(certificate)

	options := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// Signing certificates usually carry the emailProtection or the document
		// signing EKU; Go's default (server auth) would reject them.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := certificate.Verify(options); err == nil {
		return IssuerVerdict{
			Provider: ProviderPublic,
			Trusted:  true,
			Reason:   "the issuer is a recognised public authority",
		}
	} else {
		return IssuerVerdict{
			Provider:    ProviderUnknown,
			Reason:      "the issuer is not in any trusted list",
			VerifyError: err,
		}
	}
}

// Qualified reports whether the issuer appears in the trust list.
func (l TrustList) Qualified(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}

	for _, service := range l.Services {
		for _, listed := range service.Certificates {
			if listed.Equal(certificate) {
				return service.CanIssueQualifiedSignature()
			}
			// A qualified CA signs the leaf; compare issuers instead of equality.
			if listed.Subject.String() == certificate.Issuer.String() {
				return service.CanIssueQualifiedSignature()
			}
		}
	}
	return false
}

// isSelfSigned mirrors the signing-side rule: check the signature, not the
// KeyUsageCertSign bit that an end-entity certificate never carries.
func isSelfSigned(certificate *x509.Certificate) bool {
	if certificate.Issuer.String() != certificate.Subject.String() {
		return false
	}
	return certificate.CheckSignature(
		certificate.SignatureAlgorithm,
		certificate.RawTBSCertificate,
		certificate.Signature,
	) == nil
}

// Fresh reports whether the list is still within its own validity window.
//
// An expired trust list is a warning, never a silent success: the verdicts it
// produces may be based on outdated information.
func (l TrustList) Fresh(now time.Time) bool {
	if l.NextUpdate.IsZero() {
		return true
	}
	return !now.After(l.NextUpdate)
}

// ServiceCount reports how many services the list carries.
func (l TrustList) ServiceCount() int { return len(l.Services) }

// QualifiedCount reports how many services are qualified *and* granted.
//
// Counting withdrawn services would inflate the number and mislead the user
// into thinking a provider is usable when it no longer issues: "qualified" is a
// property of the listing, "granted" is whether it is in force today.
func (l TrustList) QualifiedCount() int {
	count := 0
	for _, service := range l.Services {
		if service.CanIssueQualifiedSignature() {
			count++
		}
	}
	return count
}

// ActiveCount reports how many services are granted, regardless of type.
func (l TrustList) ActiveCount() int {
	count := 0
	for _, service := range l.Services {
		if service.Status == "granted" {
			count++
		}
	}
	return count
}

// Mentions reports whether an issuer name appears as a provider in the list.
//
// It is a weaker check than Qualified(): it only says the name is listed, which
// is enough to upgrade a verdict when the library already validated the chain
// against the system roots. It is deliberately not used to grant qualified
// status on its own, because a name match is not a cryptographic proof.
func (l TrustList) Mentions(issuer string) bool {
	if issuer == "" {
		return false
	}
	for _, service := range l.Services {
		if service.ProviderName == issuer && service.CanIssueQualifiedSignature() {
			return true
		}
	}
	return false
}
