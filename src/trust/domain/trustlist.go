// Package domain models trust lists (TSL) and certificate verdicts.
//
// A verification tool has to answer "is this issuer one we recognise?" and the
// only defensible source is the official EU trust list, not a bundled guess.
// The domain keeps the list as data; fetching and parsing live in infrastructure.
package domain

import (
	"crypto/x509"
	"strings"
	"time"
)

// TrustService is one qualified service listed in a national TSL.
type TrustService struct {
	// ProviderName is the trust service provider, e.g. "ExampleTSP S.p.A.".
	ProviderName string
	// ServiceName is the specific service.
	ServiceName string
	// ServiceType follows the EU types: CA/QC for qualified certificates,
	// AdESig/AdESeal for qualified electronic signatures and seals, TS for
	// timestamps.
	ServiceType string
	// Status is granted, withdrawn or deprecated as published.
	Status string
	// StatusSince is when the current status took effect, when published.
	// A service granted after the signature was made could not have issued it,
	// so the moment is part of the evidence, not decoration.
	StatusSince time.Time
	// Qualifiers are the qualification identifiers the list publishes for this
	// service, e.g. QCWithQSCD, QCWithSSCD, QCNoQSCD. They are the machine
	// readable answer to "does the private key live in a qualified device".
	Qualifiers []string
	// Qualified reports whether the service is listed as qualified.
	Qualified bool
	// Certificates are the service's certificates, when the TSL publishes them.
	Certificates []*x509.Certificate
	// SupplyPoints are the addresses where the service is reached, as the
	// list publishes them.
	SupplyPoints []string
}

// Statuses an ETSI TS 119 612 list publishes. Only "granted" means the service
// is currently approved to issue. "accredited" is a pre-2016 status that Italy
// still carries in history and that must never be read as current approval.
const (
	// StatusGranted means the service is approved and in force.
	StatusGranted = "granted"
	// StatusWithdrawn means the service no longer issues.
	StatusWithdrawn = "withdrawn"
	// StatusDeprecated means the service must not be used for new signatures.
	StatusDeprecated = "deprecatedatnationallevel"
	// StatusRecognised means it is recognised, not qualified under eIDAS.
	StatusRecognised = "recognisedatnationallevel"
)

// HasQualifier reports whether the list publishes a qualification identifier.
func (s TrustService) HasQualifier(name string) bool {
	for _, qualifier := range s.Qualifiers {
		if qualifier == name {
			return true
		}
	}
	return false
}

// CanIssueQualifiedSignature reports whether this service issues qualified
// signature certificates.
func (s TrustService) CanIssueQualifiedSignature() bool {
	if !s.Qualified || s.Status != StatusGranted {
		return false
	}
	switch s.ServiceType {
	case "CA/QC", "AdESig", "AdESigQC":
		return true
	}
	return false
}

// CanTimestamp reports whether this service issues qualified timestamps.
//
// TSA/QTST is the qualified time-stamping authority; plain TSA is listed but not
// qualified, and a seal from it proves time without qualifying it.
func (s TrustService) CanTimestamp() bool {
	if !s.Qualified || s.Status != StatusGranted {
		return false
	}
	return s.ServiceType == "TSA/QTST"
}

// QualifiedTimestamping is a granted qualified timestamping service: its
// provider, its name and the web addresses the list gives, which most lists
// (Italy's and Spain's among them) leave out.
type QualifiedTimestamping struct {
	Provider string
	Service  string
	URLs     []string
}

// TimestampAuthorities lists the granted qualified timestamping services of
// the list, once each. The list says who is qualified, not where it answers or
// whether an account is needed (Aruba's and InfoCert's want one).
func (l TrustList) TimestampAuthorities() []QualifiedTimestamping {
	var authorities []QualifiedTimestamping
	seen := map[string]bool{}
	for _, service := range l.Services {
		key := service.ProviderName + "\x00" + service.ServiceName
		if !service.CanTimestamp() || seen[key] {
			continue
		}
		seen[key] = true
		var urls []string
		for _, point := range service.SupplyPoints {
			lower := strings.ToLower(point)
			if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
				urls = append(urls, point)
			}
		}
		authorities = append(authorities, QualifiedTimestamping{Provider: service.ProviderName, Service: service.ServiceName, URLs: urls})
	}
	return authorities
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
	// Authenticated reports whether the list itself was verified against a
	// pinned publication key. A downloaded list that fails this check is
	// inventory: it may be displayed, never used to grant trust.
	Authenticated bool
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

// IssuerCode names a verdict's reason, stable for the surfaces that put it
// in the reader's language.
type IssuerCode string

const (
	// IssuerNone: there was no certificate to judge.
	IssuerNone IssuerCode = "issuer.none"
	// IssuerSelfSigned: the certificate is its own issuer.
	IssuerSelfSigned IssuerCode = "issuer.self_signed"
	// IssuerQualified: the issuer is a qualified provider in the trusted list.
	IssuerQualified IssuerCode = "issuer.qualified"
	// IssuerNoRoots: no trusted roots to validate the chain against.
	IssuerNoRoots IssuerCode = "issuer.no_roots"
	// IssuerRecognised: the chain reaches a trusted root, not a qualified one.
	IssuerRecognised IssuerCode = "issuer.recognised"
	// IssuerUnlisted: no trusted root or list knows the issuer.
	IssuerUnlisted IssuerCode = "issuer.unlisted"
)

// IssuerVerdict describes what we know about a certificate's provenance.
type IssuerVerdict struct {
	// Code is the reason, for a translated report; Reason says it in English.
	Code     IssuerCode
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
		return IssuerVerdict{Code: IssuerNone, Provider: ProviderUnknown, Reason: "no certificate"}
	}

	if isSelfSigned(certificate) {
		return IssuerVerdict{
			Code:     IssuerSelfSigned,
			Provider: ProviderSelfSigned,
			Reason:   "the certificate is its own issuer",
		}
	}

	if list.Qualified(certificate) {
		return IssuerVerdict{
			Code:      IssuerQualified,
			Provider:  ProviderQualified,
			Trusted:   true,
			Qualified: true,
			Reason:    "the issuer is a qualified provider in the " + list.Territory + " trusted list",
		}
	}

	if roots == nil {
		return IssuerVerdict{
			Code:     IssuerNoRoots,
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
			Code:     IssuerRecognised,
			Provider: ProviderPublic,
			Trusted:  true,
			Reason:   "the issuer is a recognised public authority",
		}
	} else {
		return IssuerVerdict{
			Code:        IssuerUnlisted,
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
		if service.Status == StatusGranted {
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

// QualifiedAnchors returns the certificates of services that can issue
// qualified signatures.
//
// They are candidate trust anchors for a signature chain. Using them is what
// lets a verifier recognise "this issuer can issue qualified certificates",
// which the system web roots cannot answer: a qualified CA is usually not in
// the Mozilla/OS store.
//
// A candidate anchor is only as trustworthy as the list it came from, so the
// caller must have validated the list itself; see TrustListIntegrity.
func (l TrustList) QualifiedAnchors() []*x509.Certificate {
	var anchors []*x509.Certificate

	for _, service := range l.Services {
		if !service.CanIssueQualifiedSignature() {
			continue
		}
		anchors = append(anchors, service.Certificates...)
	}
	return anchors
}

// AnchorPool builds a certificate pool from the qualified anchors.
//
// Self-signed entries are added as roots; the rest are added to an intermediate
// pool by the caller, because a TSL also publishes intermediate and end-entity
// certificates and treating them as roots would accept chains that do not exist.
func (l TrustList) AnchorPool() (*x509.CertPool, *x509.CertPool, int) {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	added := 0

	for _, certificate := range l.QualifiedAnchors() {
		if isSelfSigned(certificate) {
			roots.AddCert(certificate)
			added++
			continue
		}
		intermediates.AddCert(certificate)
	}

	return roots, intermediates, added
}

// TrustListIntegrity describes whether a downloaded list can be relied upon.
type TrustListIntegrity struct {
	// Signed reports whether the XML carries an enveloped signature.
	Signed bool
	// SignatureValid reports whether that signature verifies against a known key.
	SignatureValid bool
	// Signer is the subject of the certificate that signed the list.
	Signer string
	// Trusted reports whether the signing certificate chains to a known root.
	Trusted bool
	// Reason explains the outcome.
	Reason string
}

// LOTLEntry is one national list advertised by the EU list of the lists.
type LOTLEntry struct {
	// Territory is the ISO code, e.g. "IT".
	Territory string
	// Location is where the list is published.
	Location string
	// MimeType and TSLType come from the LOTL and describe the format.
	MimeType string
	// Certificates are the scheme operator's signing certificates, published by
	// the Commission. They are the anchor that makes a downloaded list
	// verifiable instead of merely plausible.
	Certificates []*x509.Certificate
}

// LOTL is the EU list of the lists.
type LOTL struct {
	Entries    []LOTLEntry
	Issued     time.Time
	NextUpdate time.Time
	// Announcements are the addresses the list names in its scheme
	// information, in its order: the Official Journal notices that
	// announced the keys the Commission signs it with, and the pivot lists
	// that changed those keys since, newest first.
	Announcements []string
	// Signers are the certificates the list publishes, in its pointer to
	// itself, as the ones it may be signed with.
	Signers []*x509.Certificate
}

// ValidTerritory reports a territory code a list can be named by: two
// capital letters, as ISO 3166 and the EU list write them. A code becomes
// a file name in the cache, so nothing else is accepted.
func ValidTerritory(code string) bool {
	if len(code) != 2 {
		return false
	}
	for index := 0; index < len(code); index++ {
		if code[index] < 'A' || code[index] > 'Z' {
			return false
		}
	}
	return true
}

// Find returns the entry for a territory.
func (l LOTL) Find(territory string) (LOTLEntry, bool) {
	wanted := strings.ToUpper(strings.TrimSpace(territory))
	fallback := LOTLEntry{}
	found := false

	for _, entry := range l.Entries {
		if entry.Territory != wanted {
			continue
		}
		// A territory may publish several pointers: Spain, for instance, lists
		// both TSL.pdf and TSL.xml. Returning the first match picked the PDF and
		// rejected the whole territory as unparseable. The XML pointer is the one
		// this tool can both read and authenticate, so it is preferred; a
		// non-XML entry is only kept as a fallback so the reason stays accurate.
		if entry.XML() {
			return entry, true
		}
		if !found {
			fallback, found = entry, true
		}
	}

	return fallback, found
}

// CanSign reports whether the entry publishes at least one signing certificate.
//
// Entries that only publish a PDF have no certificates to check against, so a
// list downloaded from them cannot be authenticated and must stay inventory.
func (e LOTLEntry) CanSign() bool { return len(e.Certificates) > 0 }

// XML reports whether the published list is XML, which is what this tool parses.
func (e LOTLEntry) XML() bool {
	if strings.Contains(strings.ToLower(e.MimeType), "tsl+xml") {
		return true
	}
	return strings.HasSuffix(strings.ToLower(e.Location), ".xml")
}
