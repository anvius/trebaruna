package infrastructure

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"codeberg.org/simplicer/trebaruna/src/verification/application"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"github.com/beevik/etree"
	"github.com/digitorus/timestamp"
	dsig "github.com/russellhaering/goxmldsig"
)

// XadesVerifier checks XML signatures (XAdES, XMLDSig).
//
// It validates the cryptographic signature and extracts the XAdES qualifying
// properties. It does not decide trust: that needs the trust list and the clock,
// which belong to the use case.
type XadesVerifier struct {
	// Now is the evaluation instant.
	Now time.Time
	// Roots and Intermediates are the pools built from an authenticated trust
	// list. Nil means "no external anchor", and the issuer is then reported as
	// unknown rather than guessed.
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// Anchors are the raw certificates the trust list published.
	//
	// The pool alone is not enough. A trust list publishes the issuing
	// authority of a qualified certificate as an anchor in its own right, and
	// x509.CertPool cannot be enumerated: the certificates inside it cannot be
	// read back out to be added anywhere else. Keeping the raw certificates is
	// what lets a subordinate authority be added to the roots, the way the PDF
	// adapter does.
	Anchors []*x509.Certificate
}

// NewXadesVerifier builds the adapter.
func NewXadesVerifier() *XadesVerifier {
	return &XadesVerifier{Now: time.Now()}
}

// WithAnchors returns a copy that judges the issuer against the given pools.
//
// The return type is the application layer's extractor on purpose: a local
// interface is a different nominal type, so the use case's assertion would fail
// and the anchors would be dropped without a word.
func (v *XadesVerifier) WithAnchors(roots, intermediates *x509.CertPool) application.DocumentExtractor {
	clone := *v
	clone.Roots = roots
	clone.Intermediates = intermediates
	return &clone
}

// WithAnchorCertificates also keeps the raw certificates of the trust list.
//
// This is what makes a document that chains to a published authority verify.
// The trust list names the authority that issues qualified certificates, and
// that authority is usually an intermediate, not a root; adding it to the roots
// pool is the only way to reach it, because the certificate it signed is not
// in the document.
//
// The raw certificates are needed because x509.CertPool cannot be enumerated.
func (v *XadesVerifier) WithAnchorCertificates(roots, intermediates *x509.CertPool, anchors []*x509.Certificate) application.DocumentExtractor {
	clone := v.WithAnchors(roots, intermediates).(*XadesVerifier)
	clone.Anchors = anchors
	return clone
}

// archiveNamespace is the XAdES 1.4.1 namespace that defines ArchiveTimeStamp.
const archiveNamespace = "http://uri.etsi.org/01903/v1.4.1#"

// xadesNamespace is the XAdES 1.3.2 namespace used by the signer.
const xadesNamespace = "http://uri.etsi.org/01903/v1.3.2#"

// Extract verifies the XML signature.
func (v *XadesVerifier) Extract(path string) ([]domain.SignerReport, error) {
	if err := FileExists(path); err != nil {
		return nil, err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	document := etree.NewDocument()
	if err := document.ReadFromBytes(content); err != nil {
		return nil, fmt.Errorf("parse XML in %q: %w", path, err)
	}

	signature := findSignature(document.Root())
	if signature == nil {
		return nil, fmt.Errorf("%q carries no XML signature", path)
	}

	report := domain.SignerReport{
		FieldName: "XMLSignature",
		Format:    "XAdES",
	}

	// The certificate travels inside KeyInfo, which is what the verifier needs
	// to check the signature at all.
	certificate := extractCertificate(signature)
	describeCertificate(certificate, &report)

	// The intermediates that travel with the document are part of the evidence:
	// without them the path to the anchor cannot be built, and a signature made
	// with a properly issued certificate would read as untrusted.
	embedded := extractCertificates(signature)

	if err := validate(document, certificate); err != nil {
		report.Integrity = domain.StatusBad
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.modified",
			Status:  domain.StatusBad,
			Message: "the signed XML does not match the signature",
			Detail:  err.Error(),
		})
	} else {
		report.Integrity = domain.StatusGood
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.intact",
			Status:  domain.StatusGood,
			Message: "the signed content is unaltered",
		})
	}

	v.describeSigningTime(signature, &report)
	v.describeSignatureTimeStamp(signature, &report)
	v.describeArchiveTimeStamp(signature, &report)

	switch {
	case report.Integrity == domain.StatusBad:
		// A broken signature is the worst outcome, and it must not be masked by
		// whatever the issuer happens to be.
		report.Trust = domain.TrustBroken
	case report.SelfSigned:
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "certificate.self_signed",
			Status:  domain.StatusWarn,
			Message: "the certificate is self-signed: valid cryptography, no third-party trust",
		})
		report.Trust = domain.TrustUntrusted
	case certificate == nil:
		report.CertificateStatus = domain.StatusUnknown
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "certificate.missing",
			Status:  domain.StatusUnknown,
			Message: "the signature does not embed the signing certificate",
		})
		report.Trust = domain.TrustUntrusted
	default:
		// The XML signature verifies against the embedded certificate, which says
		// nothing about who issued it. The chain decides that, and only an
		// authenticated trust list can answer it.
		if v.chainTrusted(certificate, embedded) {
			report.CertificateStatus = domain.StatusGood
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "certificate.trusted",
				Status:  domain.StatusGood,
				Message: "the issuer is a recognised authority",
			})
			report.Trust = domain.TrustAdvanced
			break
		}
		report.CertificateStatus = domain.StatusUnknown
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "certificate.untrusted_issuer",
			Status:  domain.StatusUnknown,
			Message: "the issuer is not in any trusted list",
		})
		report.Trust = domain.TrustUntrusted
	}

	return []domain.SignerReport{report}, nil
}

// chainTrusted reports whether the certificate chains to the supplied anchors.
//
// With no anchors the answer is "no": assuming the operating system store would
// accept qualified CAs it does not contain, and assuming trust would be worse.
//
// The intermediates embedded in the document are used to build the path, because
// a certificate that travels without its chain cannot be verified against
// anything. They are evidence, not authority: only the anchors decide trust.
func (v *XadesVerifier) chainTrusted(certificate *x509.Certificate, embedded []*x509.Certificate) bool {
	if certificate == nil || v.Roots == nil {
		return false
	}

	// The intermediates that travel inside the document are what build the path
	// to the anchor. A document that carries only its leaf cannot be chained at
	// all, and most producers do exactly that.
	//
	// The pool from the trust list cannot be reused here: x509.CertPool cannot
	// be enumerated, so the certificates already in it cannot be copied into a
	// new one, and the two sets have to be merged by hand.
	intermediates := x509.NewCertPool()
	for _, candidate := range embedded {
		if candidate.Equal(certificate) {
			continue
		}
		intermediates.AddCert(candidate)
	}

	roots := v.rootsWithAnchors()
	if roots == nil {
		return false
	}

	options := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// Signing certificates carry the document-signing or email EKU, never
		// server auth, so the strict default would reject every one of them.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if !v.Now.IsZero() {
		options.CurrentTime = v.Now
	}

	_, err := certificate.Verify(options)
	return err == nil
}

// rootsWithAnchors returns the pool the chain is verified against.
//
// Every trust-list certificate is added as a root. A qualified trust list
// publishes the authority that issues qualified certificates, and that authority
// is normally an intermediate rather than a root; treating it as a root is
// trusting the list's own statement about who it vouches for.
//
// The raw certificates are needed for this because x509.CertPool cannot be
// enumerated.
func (v *XadesVerifier) rootsWithAnchors() *x509.CertPool {
	if len(v.Anchors) == 0 {
		return v.Roots
	}

	pool := x509.NewCertPool()
	for _, certificate := range v.Anchors {
		pool.AddCert(certificate)
	}
	if v.Roots != nil {
		// The system roots stay available so a document from a public authority
		// that is not in the national list still verifies.
		for _, certificate := range v.Anchors {
			v.Roots.AddCert(certificate)
		}
		return v.Roots
	}
	return pool
}

// findSignature walks the tree looking for a ds:Signature element.
func findSignature(root *etree.Element) *etree.Element {
	if root == nil {
		return nil
	}
	if root.Tag == "Signature" && root.NamespaceURI() == "http://www.w3.org/2000/09/xmldsig#" {
		return root
	}
	for _, child := range root.ChildElements() {
		if found := findSignature(child); found != nil {
			return found
		}
	}
	return nil
}

// localName returns the tag without its namespace prefix.
func localName(element *etree.Element) string {
	// etree splits "ds:Signature" into Space="ds" and Tag="Signature".
	return element.Tag
}

// extractCertificate reads the first X509Certificate in KeyInfo.
//
// The tree is walked by hand instead of using an XPath query: etree's
// SelectElements("//X509Certificate") returns nothing for the namespaced tree
// our signer emits, and a silent empty result would report every XAdES file as
// having no certificate.
// extractCertificate returns the signing certificate.
//
// The signing certificate is the one the signature was actually made with: it is
// the first X509Certificate in KeyInfo, and the one whose public key validates
// the signature value. When a document embeds a full chain, the first entry is
// still the leaf, because that is the order every XAdES producer uses.
func extractCertificate(signature *etree.Element) *x509.Certificate {
	certificates := extractCertificates(signature)
	if len(certificates) == 0 {
		return nil
	}
	return certificates[0]
}

// extractCertificates returns every certificate embedded in the KeyInfo.
//
// A document that chains to a real authority embeds the whole chain: leaf first,
// then the intermediates. Reading only the leaf is enough to check the
// signature, but not enough to build the path to the anchor — and a verifier
// that cannot build the path will call every foreign certificate untrusted no
// matter how well signed it is.
func extractCertificates(signature *etree.Element) []*x509.Certificate {
	var certificates []*x509.Certificate

	walk(signature, func(element *etree.Element) {
		if element.Tag != "X509Certificate" || element.NamespaceURI() != "http://www.w3.org/2000/09/xmldsig#" {
			return
		}
		certificate, err := x509.ParseCertificate(decodeBase64Element(element.Text()))
		if err != nil {
			return
		}
		// The same certificate can appear twice when a document carries several
		// signatures over the same key material.
		for _, existing := range certificates {
			if existing.Equal(certificate) {
				return
			}
		}
		certificates = append(certificates, certificate)
	})

	return certificates
}

// walk visits every descendant depth-first.
func walk(element *etree.Element, visit func(*etree.Element)) {
	if element == nil {
		return
	}
	visit(element)
	for _, child := range element.ChildElements() {
		walk(child, visit)
	}
}

// validate checks the signature with the embedded certificate as the trust anchor.
//
// Using the embedded certificate as the store is deliberate: this step answers
// "does the signature match this certificate", not "is this certificate
// trusted". Trust is a separate question with a separate source.
func validate(document *etree.Document, certificate *x509.Certificate) error {
	if certificate == nil {
		return fmt.Errorf("no signing certificate to validate against")
	}

	store := &singleCertificateStore{certificate: certificate}
	context := dsig.NewDefaultValidationContext(store)

	// Id attributes in XAdES are spelled "Id", which is what the signer emits.
	context.IdAttribute = "Id"
	// The embedded leaf is used only to verify the XMLDSig value. Its validity
	// and issuer trust are reported separately, not as tampered content.
	context.Clock = dsig.NewFakeClockAt(certificate.NotBefore)

	_, err := context.Validate(document.Root())
	return err
}

// singleCertificateStore exposes exactly one certificate.
type singleCertificateStore struct {
	certificate *x509.Certificate
}

// Certificates returns the embedded certificate as the only anchor.
func (s *singleCertificateStore) Certificates() ([]*x509.Certificate, error) {
	return []*x509.Certificate{s.certificate}, nil
}

// describeSigningTime reads xades:SigningTime.
//
// XAdES-BES carries the claimed time only. Without a SignatureTimeStamp it is
// the signer's word, so the report says exactly that.
func (v *XadesVerifier) describeSigningTime(signature *etree.Element, report *domain.SignerReport) {
	walk(signature, func(element *etree.Element) {
		if report.SignedAt.IsZero() && element.Tag == "SigningTime" && element.NamespaceURI() == xadesNamespace {
			if parsed, err := time.Parse(time.RFC3339, element.Text()); err == nil {
				report.SignedAt = parsed
			}
		}
	})
}

// describeSignatureTimeStamp reads xades:SignatureTimeStamp and checks it.
//
// Two things must hold, and only the first is visible at a glance: the token must
// be a real token, and its imprint must cover the ds:SignatureValue that is
// actually in this file. A token lifted from another signature parses perfectly
// and proves nothing, which is why the imprint is recomputed here rather than
// trusted from the report of whoever produced the document.
func (v *XadesVerifier) describeSignatureTimeStamp(signature *etree.Element, report *domain.SignerReport) {
	var tokenText string
	walk(signature, func(element *etree.Element) {
		if tokenText == "" && element.Tag == "EncapsulatedTimeStamp" && element.NamespaceURI() == xadesNamespace {
			tokenText = element.Text()
		}
	})
	if tokenText == "" {
		return
	}

	tokenDER, err := base64.StdEncoding.DecodeString(tokenText)
	if err != nil {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the timestamp token is not valid base64",
			Detail:  err.Error(),
		})
		return
	}

	token, err := timestamp.Parse(tokenDER)
	if err != nil {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the timestamp token cannot be parsed or does not verify",
			Detail:  err.Error(),
		})
		return
	}

	signatureValue := findSignatureValue(signature)
	if signatureValue == nil {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the signature has no SignatureValue for the token to cover",
		})
		return
	}

	// The covered content is the element as serialised in this document.
	covered := serialiseElement(signatureValue)
	hasher := token.HashAlgorithm.New()
	if !token.HashAlgorithm.Available() {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the token uses a digest algorithm this build does not support",
		})
		return
	}
	hasher.Write(covered)
	if !bytes.Equal(hasher.Sum(nil), token.HashedMessage) {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the timestamp covers a different signature value",
		})
		return
	}

	report.Timestamped = true
	report.SignedAt = token.Time

	facts := ReadTimestamp(token)
	report.TimestampEvidence = domain.TimestampEvidence{
		Bound:                   true,
		CertificateCanTimestamp: facts.CanTimestamp,
		CertificateIssuerDN:     facts.SignerIssuerDN,
		Certificate:             facts.Signer,
	}
	if facts.Signer != nil {
		report.TimestampAuthority = facts.Signer.Subject.CommonName
	}

	report.Findings = append(report.Findings, domain.Finding{
		Code:    "timestamp.bound",
		Status:  domain.StatusGood,
		Message: "the timestamp is bound to this signature",
	})
	if !facts.CanTimestamp {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.not_timestamping_certificate",
			Status:  domain.StatusWarn,
			Message: "the timestamp certificate lacks the timeStamping key usage",
		})
	}
}

// describeArchiveTimeStamp reads xades141:ArchiveTimeStamp.
//
// It is a different token from the signature timestamp: it covers every object
// of the signature, not the signature value, so it reports that the archival
// level exists and names its authority. Verifying its imprint would mean
// reproducing the whole §5.5.2.2 octet stream, which the signer builds; what is
// asserted here is that the token is real and that it parses.
func (v *XadesVerifier) describeArchiveTimeStamp(signature *etree.Element, report *domain.SignerReport) {
	var tokenText string
	walk(signature, func(element *etree.Element) {
		if tokenText == "" && element.Tag == "ArchiveTimeStamp" && element.NamespaceURI() == archiveNamespace {
			for _, child := range element.ChildElements() {
				if child.Tag == "EncapsulatedTimeStamp" {
					tokenText = child.Text()
				}
			}
		}
	})
	if tokenText == "" {
		return
	}

	tokenDER, err := base64.StdEncoding.DecodeString(tokenText)
	if err != nil {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the archive timestamp is not valid base64",
			Detail:  err.Error(),
		})
		return
	}

	token, err := timestamp.Parse(tokenDER)
	if err != nil {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the archive timestamp cannot be parsed or does not verify",
			Detail:  err.Error(),
		})
		return
	}

	report.Findings = append(report.Findings, domain.Finding{
		Code:    "timestamp.archival",
		Status:  domain.StatusGood,
		Message: "the signature carries an archive timestamp (XAdES-A)",
		Detail:  token.Time.UTC().Format(time.RFC3339),
	})
}

// findSignatureValue locates ds:SignatureValue inside the signature.
func findSignatureValue(signature *etree.Element) *etree.Element {
	if signature == nil {
		return nil
	}
	if signature.Tag == "SignatureValue" && signature.NamespaceURI() == "http://www.w3.org/2000/09/xmldsig#" {
		return signature
	}
	for _, child := range signature.ChildElements() {
		if found := findSignatureValue(child); found != nil {
			return found
		}
	}
	return nil
}

// serialiseElement renders an element exactly as it sits in the document.
//
// The token in the file covers the bytes a reader sees, so the digest is computed
// over those bytes and not over a re-indented copy.
func serialiseElement(element *etree.Element) []byte {
	document := etree.NewDocument()
	document.SetRoot(element.Copy())
	document.Indent(0)
	output, err := document.WriteToBytes()
	if err != nil {
		return nil
	}
	start := bytes.Index(output, []byte("<ds:SignatureValue"))
	end := bytes.LastIndex(output, []byte("</ds:SignatureValue>"))
	if start < 0 || end < 0 {
		return nil
	}
	return output[start : end+len("</ds:SignatureValue>")]
}

// compile-time check.
var _ SignatureExtractor = (*XadesVerifier)(nil)
