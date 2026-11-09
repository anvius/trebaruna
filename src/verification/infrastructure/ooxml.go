package infrastructure

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/opc"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	"codeberg.org/simplicer/trebaruna/src/verification/application"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// OoxmlVerifier checks the signatures of Office Open XML files (ECMA-376
// Part 2, §13): each signature part the package's origin names is judged
// as an XML signature, then the parts its Manifest lists against their
// digests, and the parts no signature covers are named, so a part added
// after signing cannot pass for signed.
type OoxmlVerifier struct {
	xades *XadesVerifier
}

// NewOoxmlVerifier builds the adapter over the XML signature verifier.
func NewOoxmlVerifier(xades *XadesVerifier) *OoxmlVerifier {
	return &OoxmlVerifier{xades: xades}
}

// WithAnchors validates the signatures' chains against the pools.
func (v *OoxmlVerifier) WithAnchors(roots, intermediates *x509.CertPool) application.DocumentExtractor {
	return &OoxmlVerifier{xades: v.xades.WithAnchors(roots, intermediates).(*XadesVerifier)}
}

// WithAnchorCertificates also keeps the trust list's raw certificates.
func (v *OoxmlVerifier) WithAnchorCertificates(roots, intermediates *x509.CertPool, anchors []*x509.Certificate) application.DocumentExtractor {
	return &OoxmlVerifier{xades: v.xades.WithAnchorCertificates(roots, intermediates, anchors).(*XadesVerifier)}
}

// Extract reports every signature of the package; an unsigned one has
// none.
func (v *OoxmlVerifier) Extract(path string) ([]domain.SignerReport, error) {
	if err := FileExists(path); err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	pkg, err := opc.Open(content)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", path, err)
	}
	parts, err := pkg.SignatureParts()
	if err != nil {
		return nil, fmt.Errorf("%q: %w", path, err)
	}

	// References outside the package are refused: a package signature
	// reaches its parts through the Manifest, never the file system.
	inPackage := v.xades.resolvingWith(func(uri string) ([]byte, error) {
		return nil, fmt.Errorf("%w: %s: a package signature reaches parts through its Manifest", xmldsig.ErrUnverifiable, uri)
	})
	covered := map[string]bool{}
	var reports []domain.SignerReport
	for _, part := range parts {
		data, found := pkg.Part(part)
		if !found {
			return nil, fmt.Errorf("%q names the signature %s, which it does not hold", path, part)
		}
		document := etree.NewDocument()
		if err := document.ReadFromBytes(data); err != nil {
			return nil, fmt.Errorf("%q: the signature %s is not XML: %w", path, part, err)
		}
		for _, signature := range xmldsig.Signatures(document) {
			report := inPackage.report(document, signature, part)
			report.FieldName = strings.TrimPrefix(part, "/")
			describeSignatureTime(signature, &report)
			describeManifests(pkg, signature, &report, covered)
			reports = append(reports, report)
		}
	}

	if unsigned := pkg.Unsigned(covered); len(unsigned) > 0 {
		for index := range reports {
			reports[index].Findings = append(reports[index].Findings, domain.Finding{
				Code:    "container.unsigned_files",
				Status:  domain.StatusWarn,
				Message: "the container holds files no signature covers",
				Detail:  strings.Join(unsigned, ", "),
			})
		}
	}
	return reports, nil
}

// describeManifests checks the Manifests of the objects SignedInfo
// references: only those are covered by the signature value, so a Manifest
// anywhere else proves nothing.
func describeManifests(pkg *opc.Package, signature *etree.Element, report *domain.SignerReport, covered map[string]bool) {
	var parts, libxmlsec []string
	var failure error
	for _, reference := range signature.FindElements("./SignedInfo/Reference") {
		uri := reference.SelectAttrValue("URI", "")
		object := elementWithID(signature, strings.TrimPrefix(uri, "#"))
		if !strings.HasPrefix(uri, "#") || object == nil || object.Tag != "Object" {
			continue
		}
		for _, manifest := range object.SelectElements("Manifest") {
			check, err := pkg.CheckManifest(manifest)
			parts = append(parts, check.Covered...)
			libxmlsec = append(libxmlsec, check.LibxmlsecForm...)
			if err != nil && failure == nil {
				failure = err
			}
		}
	}
	for _, part := range parts {
		covered[part] = true
	}

	switch {
	case failure == nil:
	case errors.Is(failure, xmldsig.ErrUnverifiable):
		if report.Integrity == domain.StatusGood {
			report.Integrity = domain.StatusUnknown
		}
		report.Findings = append(withoutFinding(report.Findings, "signature.intact"), domain.Finding{
			Code:    "signature.unverifiable",
			Status:  domain.StatusUnknown,
			Message: "the signature uses something trebaruna cannot check",
			Detail:  failure.Error(),
		})
	default:
		report.Integrity = domain.StatusBad
		report.Trust = domain.TrustBroken
		report.Findings = append(withoutFinding(report.Findings, "signature.intact"), domain.Finding{
			Code:    "signature.modified",
			Status:  domain.StatusBad,
			Message: "the signed XML does not match the signature",
			Detail:  failure.Error(),
		})
	}
	if len(libxmlsec) > 0 {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "relationships.libxmlsec_form",
			Status:  domain.StatusWarn,
			Message: "the package relationships are digested as libxmlsec (LibreOffice) computes them, not as ECMA-376 says: Microsoft Office may report the signature broken",
			Detail:  strings.Join(libxmlsec, ", "),
		})
	}
	names := make([]string, 0, len(parts))
	for _, part := range parts {
		names = append(names, strings.TrimPrefix(part, "/"))
	}
	report.Findings = append(report.Findings, domain.Finding{
		Code:    "container.covers",
		Status:  domain.StatusGood,
		Message: "the signature covers these files of the container",
		Detail:  strings.Join(names, ", "),
	})
}

// describeSignatureTime reads OPC's SignatureTime, the time the signer's
// computer claimed, when the signature has no XAdES SigningTime: Office 2007
// and plain XMLDSig signatures carry only that.
func describeSignatureTime(signature *etree.Element, report *domain.SignerReport) {
	walk(signature, func(element *etree.Element) {
		if !report.SignedAt.IsZero() || element.Tag != "SignatureTime" || element.NamespaceURI() != opc.NamespaceSignature {
			return
		}
		if value := element.SelectElement("Value"); value != nil {
			if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value.Text())); err == nil {
				report.SignedAt = parsed
			}
		}
	})
}

// elementWithID finds the element of a signature with an Id.
func elementWithID(root *etree.Element, id string) *etree.Element {
	var found *etree.Element
	walk(root, func(element *etree.Element) {
		if found == nil && id != "" && element.SelectAttrValue("Id", "") == id {
			found = element
		}
	})
	return found
}
