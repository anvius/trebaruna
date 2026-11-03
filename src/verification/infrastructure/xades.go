package infrastructure

import (
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"codeberg.org/simplicer/firma-it/src/verification/domain"
	"github.com/beevik/etree"
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
}

// NewXadesVerifier builds the adapter.
func NewXadesVerifier() *XadesVerifier {
	return &XadesVerifier{Now: time.Now()}
}

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
		// The chain is checked by the use case against the trust list; here it is
		// enough to record that a certificate exists and verifies the signature.
		report.CertificateStatus = domain.StatusUnknown
		report.Trust = domain.TrustUntrusted
	}

	return []domain.SignerReport{report}, nil
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
func extractCertificate(signature *etree.Element) *x509.Certificate {
	var found *x509.Certificate

	walk(signature, func(element *etree.Element) {
		if found != nil || element.Tag != "X509Certificate" || element.NamespaceURI() != "http://www.w3.org/2000/09/xmldsig#" {
			return
		}
		if certificate, err := x509.ParseCertificate(decodeBase64Element(element.Text())); err == nil {
			found = certificate
		}
	})
	return found
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

// compile-time check.
var _ SignatureExtractor = (*XadesVerifier)(nil)
