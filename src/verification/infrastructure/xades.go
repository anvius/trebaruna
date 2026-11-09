package infrastructure

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/publickey"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	"codeberg.org/simplicer/trebaruna/src/verification/application"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	"github.com/beevik/etree"
	"github.com/digitorus/timestamp"
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
	// contentPath is the document a detached signature signs, when the
	// person names it; otherwise the file the reference names is looked for
	// beside the signature.
	contentPath string
	// containerRoot, inside an ASiC container, is where references resolve:
	// paths relative to the container's root, folders included, never out.
	containerRoot string
	// resolve, when set, resolves every reference to content outside the
	// signature instead (a package's own rules).
	resolve xmldsig.Resolver
}

// resolvingWith resolves the references to content outside the signature
// with resolve.
func (v *XadesVerifier) resolvingWith(resolve xmldsig.Resolver) *XadesVerifier {
	clone := *v
	clone.resolve = resolve
	return &clone
}

// inContainer resolves references from the root of an unpacked container.
func (v *XadesVerifier) inContainer(root string) *XadesVerifier {
	clone := *v
	clone.containerRoot = root
	return &clone
}

// WithContent checks a detached signature against the document at path.
func (v *XadesVerifier) WithContent(path string) application.DocumentExtractor {
	clone := *v
	clone.contentPath = path
	return &clone
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
	publickey.Complete(anchors...)
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

	signatures := xmldsig.Signatures(document)
	if len(signatures) == 0 {
		return nil, fmt.Errorf("%q carries no XML signature", path)
	}
	// Every signature is judged: a co-signed document carries several, and
	// reporting the first alone would vouch for the others unseen.
	names := map[*etree.Element]string{}
	for index, signature := range signatures {
		names[signature] = "XMLSignature"
		if len(signatures) > 1 {
			names[signature] = fmt.Sprintf("XMLSignature #%d", index+1)
		}
	}
	reports := make([]domain.SignerReport, 0, len(signatures))
	for _, signature := range signatures {
		report := v.report(document, signature, path)
		report.FieldName = names[signature]
		if target := countersigned(document, signature); target != nil {
			report.Countersigns = names[target]
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// report judges one signature of the document.
func (v *XadesVerifier) report(document *etree.Document, signature *etree.Element, path string) domain.SignerReport {
	report := domain.SignerReport{
		FieldName: "XMLSignature",
		Format:    xmlSignatureFormat(signature),
		Declared:  xadesDeclarations(signature),
	}

	// The certificate travels inside KeyInfo, which is what the verifier needs
	// to check the signature at all.
	certificate := extractCertificate(signature)
	describeCertificate(certificate, &report)

	// The intermediates that travel with the document are part of the evidence:
	// without them the path to the anchor cannot be built, and a signature made
	// with a properly issued certificate would read as untrusted.
	embedded := extractCertificates(signature)

	var used []string
	resolve := v.beside(path, &used)
	if v.resolve != nil {
		resolve = v.resolve
	}
	err := validate(document, signature, certificate, resolve)
	if len(used) > 0 {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "content.detached",
			Status:  domain.StatusGood,
			Message: "detached signature checked against the document beside it",
			Detail:  strings.Join(used, ", "),
		})
	}
	describeIntegrity(err, &report)
	if report.Integrity == domain.StatusGood {
		describeSigningCertificate(signature, certificate, &report)
		describeCoverage(document, signature, func(other *etree.Element) bool {
			return validate(document, other, extractCertificate(other), resolve) == nil
		}, &report)
	}

	v.describeSigningTime(signature, &report)
	v.describeSignatureTimeStamp(signature, &report)
	v.describeArchiveTimeStamp(document, signature, resolve, &report)

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
	// Bytes that could not be compared (a referenced file not at hand) prove
	// no cryptography: "untrusted" would say it holds. The certificate
	// findings above still stand.
	if report.Integrity == domain.StatusUnknown {
		report.Trust = domain.TrustUnknown
	}

	return report
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
	if err != nil && involvesBrainpool(append(append([]*x509.Certificate{certificate}, embedded...), v.Anchors...)) {
		at := options.CurrentTime
		if at.IsZero() {
			at = time.Now()
		}
		return brainpoolChainOf(certificate, embedded, v.Anchors, at) == nil
	}
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
		certificate, err := brainpool.ParseCertificate(decodeBase64Element(element.Text()))
		if err != nil {
			return
		}
		publickey.Complete(certificate)
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
// xmlSignatureFormat names the signature: XAdES when it carries qualifying
// properties, plain XMLDSig otherwise.
func xmlSignatureFormat(signature *etree.Element) string {
	format := "XMLDSig"
	walk(signature, func(element *etree.Element) {
		if element.Tag == "QualifyingProperties" && strings.HasPrefix(element.NamespaceURI(), "http://uri.etsi.org/01903/") {
			format = "XAdES"
		}
	})
	return format
}

// validate checks the XML signature completely: every reference it makes,
// the signed properties included, and the value over SignedInfo, against the
// embedded certificate. This answers "does the signature match this
// certificate", not "is this certificate trusted": trust is a separate
// question with a separate source.
func validate(document *etree.Document, signature *etree.Element, certificate *x509.Certificate, resolve xmldsig.Resolver) error {
	if certificate == nil {
		return fmt.Errorf("%w: no signing certificate to validate against", xmldsig.ErrUnverifiable)
	}
	return xmldsig.Check(document, signature, publickey.Of(certificate), resolve)
}

// beside resolves a detached reference: the document the person named, or
// the file the reference names in the signature's own directory. Only a
// plain file name is followed: no directories, no "..", no address, which
// is never fetched. Inside a container the name is a path from its root.
// used receives each file that was read.
func (v *XadesVerifier) beside(signaturePath string, used *[]string) xmldsig.Resolver {
	return func(uri string) ([]byte, error) {
		path := v.contentPath
		switch {
		case path != "":
		case v.containerRoot != "":
			name, inside := containerPath(uri)
			if !inside {
				return nil, fmt.Errorf("%w: %s is not a file of the container", xmldsig.ErrContentMissing, uri)
			}
			path = filepath.Join(v.containerRoot, filepath.FromSlash(name))
		default:
			name, err := url.PathUnescape(uri)
			if err != nil || name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) {
				return nil, fmt.Errorf("%w: %s is not a file beside the signature", xmldsig.ErrContentMissing, uri)
			}
			path = filepath.Join(filepath.Dir(signaturePath), name)
		}
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %s", xmldsig.ErrContentMissing, path)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", xmldsig.ErrContentMissing, err)
		}
		*used = append(*used, path)
		return content, nil
	}
}

// describeIntegrity reports what the check found: intact, modified, or not
// checkable here (an algorithm trebaruna does not implement, or signed
// content it does not have), which is not the same as modified (ADR-0005).
func describeIntegrity(err error, report *domain.SignerReport) {
	switch {
	case err == nil:
		report.Integrity = domain.StatusGood
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.intact",
			Status:  domain.StatusGood,
			Message: "the signed content is unaltered",
		})
	case errors.Is(err, xmldsig.ErrContentMissing):
		report.Integrity = domain.StatusUnknown
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "content.missing",
			Status:  domain.StatusUnknown,
			Message: "detached signature: the signed document is needed to compare its bytes",
			Detail:  err.Error(),
		})
	case errors.Is(err, xmldsig.ErrUnverifiable):
		report.Integrity = domain.StatusUnknown
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.unverifiable",
			Status:  domain.StatusUnknown,
			Message: "the signature uses something trebaruna cannot check",
			Detail:  err.Error(),
		})
	default:
		report.Integrity = domain.StatusBad
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "signature.modified",
			Status:  domain.StatusBad,
			Message: "the signed XML does not match the signature",
			Detail:  err.Error(),
		})
	}
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

	token, err := parseTimeStamp(tokenDER)
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

	if !token.HashAlgorithm.Available() {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the token uses a digest algorithm this build does not support",
		})
		return
	}
	covers := func(content []byte) bool {
		hasher := token.HashAlgorithm.New()
		hasher.Write(content)
		return bytes.Equal(hasher.Sum(nil), token.HashedMessage)
	}
	// The token covers ds:SignatureValue in its canonical form where it
	// stands, with the C14N the SignatureTimeStamp declares (EN 319 132-1,
	// 5.4.1.3). trebaruna before 0.38.2 timestamped the element as written,
	// which only it accepts: that is told, not hidden.
	canonical, canonicalErr := xmldsig.Canonicalize(signatureValue, signatureTimeStampCanonicalization(signature), "")
	legacy := false
	switch {
	case canonicalErr == nil && covers(canonical):
	case covers(serialiseElement(signatureValue)):
		legacy = true
	default:
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
	if legacy {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.legacy_form",
			Status:  domain.StatusWarn,
			Message: "the timestamp covers the signature value as trebaruna wrote it before 0.38.2, not its canonical form: other validators will not accept it",
		})
	}
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
// of the signature, not the signature value. Its imprint is checked against the
// EN 319 132-1 §5.5.2.2 octet stream, rebuilt with the signer's own
// xmldsig.ArchiveTimeStampInput: what it sealed changed or is gone, and the
// report says timestamp.archive_unbound.
func (v *XadesVerifier) describeArchiveTimeStamp(document *etree.Document, signature *etree.Element, resolve xmldsig.Resolver, report *domain.SignerReport) {
	var archive *etree.Element
	var tokenText string
	algorithm := xmldsig.C14N10
	walk(signature, func(element *etree.Element) {
		if archive == nil && element.Tag == "ArchiveTimeStamp" && element.NamespaceURI() == archiveNamespace {
			archive = element
			for _, child := range element.ChildElements() {
				switch child.Tag {
				case "EncapsulatedTimeStamp":
					tokenText = child.Text()
				case "CanonicalizationMethod":
					algorithm = child.SelectAttrValue("Algorithm", algorithm)
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

	token, err := parseTimeStamp(tokenDER)
	if err != nil {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.invalid",
			Status:  domain.StatusBad,
			Message: "the archive timestamp cannot be parsed or does not verify",
			Detail:  err.Error(),
		})
		return
	}

	// The token must seal what EN 319 132-1 says it seals: the signature's
	// references, its value and every property written before it.
	input, err := xmldsig.ArchiveTimeStampInput(document, signature, resolve, algorithm, archive)
	if err == nil {
		err = imprintOf(token, input)
	}
	if err != nil {
		report.Findings = append(report.Findings, domain.Finding{
			Code:    "timestamp.archive_unbound",
			Status:  domain.StatusWarn,
			Message: "the archive timestamp does not cover this signature as EN 319 132-1 reads: it proves nothing about it",
			Detail:  err.Error(),
		})
		return
	}
	report.Findings = append(report.Findings, domain.Finding{
		Code:    "timestamp.archival",
		Status:  domain.StatusGood,
		Message: "the signature carries an archive timestamp (XAdES-A) that covers it",
		Detail:  token.Time.UTC().Format(time.RFC3339),
	})
}

// signatureTimeStampCanonicalization is the C14N a SignatureTimeStamp
// declares, inclusive C14N 1.0 when it names none.
func signatureTimeStampCanonicalization(signature *etree.Element) string {
	algorithm := xmldsig.C14N10
	walk(signature, func(element *etree.Element) {
		if element.Tag != "SignatureTimeStamp" || element.NamespaceURI() != xadesNamespace {
			return
		}
		for _, child := range element.ChildElements() {
			if child.Tag == "CanonicalizationMethod" {
				algorithm = child.SelectAttrValue("Algorithm", algorithm)
			}
		}
	})
	return algorithm
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

// imprintOf checks that a token's imprint is the digest of what it must
// seal.
func imprintOf(token *timestamp.Timestamp, sealed []byte) error {
	if !token.HashAlgorithm.Available() {
		return fmt.Errorf("the token's digest algorithm is not available")
	}
	hasher := token.HashAlgorithm.New()
	hasher.Write(sealed)
	if !bytes.Equal(hasher.Sum(nil), token.HashedMessage) {
		return fmt.Errorf("its imprint is not the digest of the signature it is attached to")
	}
	return nil
}
