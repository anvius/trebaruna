package infrastructure

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	"codeberg.org/simplicer/trebaruna/src/verification/application"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// ASiC media types and the namespace of its manifests (ETSI EN 319 162-1).
const (
	asicSimpleMediaType   = "application/vnd.etsi.asic-s+zip"
	asicExtendedMediaType = "application/vnd.etsi.asic-e+zip"
	asicNamespace         = "http://uri.etsi.org/02918/v1.2.1#"
	// asicEntryLimit bounds each unpacked entry: a container is read whole,
	// and a crafted one must not fill the disk.
	asicEntryLimit = 512 << 20
)

// AsicVerifier checks ASiC containers (ETSI EN 319 162-1): a ZIP holding
// documents and, under META-INF, the signatures over them. Each signature
// is judged by the CAdES or XAdES verifier against the files it covers, and
// a file no signature covers is reported, so a container cannot pass off an
// added document as signed.
type AsicVerifier struct {
	cades *CadesVerifier
	xades *XadesVerifier
	// odf reads OpenDocument packages instead: their signatures live in
	// META-INF/documentsignatures.xml and cover every stream, mimetype too.
	odf bool
}

// NewAsicVerifier builds the adapter over the signature verifiers.
func NewAsicVerifier(cades *CadesVerifier, xades *XadesVerifier) *AsicVerifier {
	return &AsicVerifier{cades: cades, xades: xades}
}

// NewOdfVerifier checks the signatures of OpenDocument files (OASIS ODF
// 1.2, Part 3) the same way: each against the streams it covers, and the
// streams no signature covers named.
func NewOdfVerifier(xades *XadesVerifier) *AsicVerifier {
	return &AsicVerifier{cades: NewCadesVerifier(), xades: xades, odf: true}
}

// WithAnchors validates the signatures' chains against the pools.
func (v *AsicVerifier) WithAnchors(roots, intermediates *x509.CertPool) application.DocumentExtractor {
	return &AsicVerifier{
		cades: v.cades.WithAnchors(roots, intermediates).(*CadesVerifier),
		xades: v.xades.WithAnchors(roots, intermediates).(*XadesVerifier),
		odf:   v.odf,
	}
}

// WithAnchorCertificates also keeps the trust list's raw certificates.
func (v *AsicVerifier) WithAnchorCertificates(roots, intermediates *x509.CertPool, anchors []*x509.Certificate) application.DocumentExtractor {
	return &AsicVerifier{
		cades: v.cades.WithAnchorCertificates(roots, intermediates, anchors).(*CadesVerifier),
		xades: v.xades.WithAnchorCertificates(roots, intermediates, anchors).(*XadesVerifier),
		odf:   v.odf,
	}
}

// container is an unpacked ASiC container.
type container struct {
	extended bool
	// root is a private directory holding the entries.
	root string
	// documents are the data objects, by their path in the container.
	documents []string
	// meta are the entries under META-INF.
	meta []string
}

// Extract reports every signature of the container.
func (v *AsicVerifier) Extract(archivePath string) ([]domain.SignerReport, error) {
	unpacked, err := unpack(archivePath, v.odf)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(unpacked.root)

	var reports []domain.SignerReport
	covered := map[string]bool{}
	for _, entry := range unpacked.meta {
		base := strings.ToLower(path.Base(entry))
		var found []domain.SignerReport
		var covers []string
		switch {
		case strings.HasPrefix(base, "signature") && strings.HasSuffix(base, ".p7s"):
			found, covers, err = v.cadesSignature(unpacked, entry)
		case strings.Contains(base, "signatures") && strings.HasSuffix(base, ".xml"):
			found, covers, err = v.xadesSignatures(unpacked, entry)
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, name := range covers {
			covered[name] = true
		}
		for index := range found {
			found[index].FieldName = entry
			// The unpacked copies' paths mean nothing to the person; which
			// files of the container are covered is said below.
			found[index].Findings = withoutFinding(found[index].Findings, "content.detached")
			found[index].Findings = append(found[index].Findings, domain.Finding{
				Code:    "container.covers",
				Status:  domain.StatusGood,
				Message: "the signature covers these files of the container",
				Detail:  strings.Join(covers, ", "),
			})
		}
		reports = append(reports, found...)
	}
	switch {
	case len(reports) == 0 && v.odf:
		// An OpenDocument file without signatures is an ordinary document.
		return nil, nil
	case len(reports) == 0:
		return nil, fmt.Errorf("%q is a container with no CAdES or XAdES signature under META-INF", archivePath)
	}

	var unsigned []string
	for _, document := range unpacked.documents {
		if !covered[document] {
			unsigned = append(unsigned, document)
		}
	}
	if len(unsigned) > 0 {
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

// cadesSignature judges a CAdES signature: over the ASiCManifest that names
// it (ASiC-E), whose digests must match the files, or over the one document
// of an ASiC-S container.
func (v *AsicVerifier) cadesSignature(unpacked container, entry string) ([]domain.SignerReport, []string, error) {
	signaturePath := unpacked.file(entry)
	manifest, references, err := manifestFor(unpacked, entry)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case manifest != "":
		reports, err := v.cades.WithContent(unpacked.file(manifest)).Extract(signaturePath)
		if err != nil {
			return nil, nil, err
		}
		covers := make([]string, 0, len(references))
		for _, reference := range references {
			covers = append(covers, reference.name)
		}
		for index := range reports {
			checkManifest(unpacked, references, &reports[index])
		}
		return reports, covers, nil
	case !unpacked.extended && len(unpacked.documents) == 1:
		reports, err := v.cades.WithContent(unpacked.file(unpacked.documents[0])).Extract(signaturePath)
		return reports, unpacked.documents, err
	}
	// Nothing says what the signature covers: its bytes cannot be compared.
	reports, err := v.cades.Extract(signaturePath)
	return reports, nil, err
}

// xadesSignatures judges the XAdES signatures of a signatures file, their
// references resolved inside the container.
func (v *AsicVerifier) xadesSignatures(unpacked container, entry string) ([]domain.SignerReport, []string, error) {
	signaturePath := unpacked.file(entry)
	reports, err := v.xades.inContainer(unpacked.root).Extract(signaturePath)
	if err != nil {
		return nil, nil, err
	}
	document := etree.NewDocument()
	if err := document.ReadFromFile(signaturePath); err != nil {
		return nil, nil, err
	}
	var covers []string
	for _, signature := range xmldsig.Signatures(document) {
		for _, reference := range signature.FindElements("./SignedInfo/Reference") {
			uri := reference.SelectAttrValue("URI", "")
			if name, inside := containerPath(uri); inside && uri != "" && !strings.HasPrefix(uri, "#") {
				covers = append(covers, name)
			}
		}
	}
	return reports, covers, nil
}

// manifestReference is a data object an ASiCManifest lists.
type manifestReference struct {
	name, algorithm string
	digest          []byte
}

// manifestFor finds the ASiCManifest whose SigReference names the signature.
func manifestFor(unpacked container, signature string) (string, []manifestReference, error) {
	for _, entry := range unpacked.meta {
		base := strings.ToLower(path.Base(entry))
		if !strings.HasPrefix(base, "asicmanifest") || !strings.HasSuffix(base, ".xml") {
			continue
		}
		document := etree.NewDocument()
		if err := document.ReadFromFile(unpacked.file(entry)); err != nil {
			return "", nil, fmt.Errorf("read %s: %w", entry, err)
		}
		root := document.Root()
		if root == nil || root.Tag != "ASiCManifest" || root.NamespaceURI() != asicNamespace {
			continue
		}
		signed := root.SelectElement("SigReference")
		if signed == nil {
			continue
		}
		if name, _ := containerPath(signed.SelectAttrValue("URI", "")); name != signature {
			continue
		}
		var references []manifestReference
		for _, element := range root.SelectElements("DataObjectReference") {
			name, inside := containerPath(element.SelectAttrValue("URI", ""))
			if !inside {
				return "", nil, fmt.Errorf("%s names %q, outside the container", entry, element.SelectAttrValue("URI", ""))
			}
			method, value := element.SelectElement("DigestMethod"), element.SelectElement("DigestValue")
			if method == nil || value == nil {
				return "", nil, fmt.Errorf("%s lists %s without its digest", entry, name)
			}
			digest, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value.Text()), ""))
			if err != nil {
				return "", nil, fmt.Errorf("%s: the digest of %s is not Base64", entry, name)
			}
			references = append(references, manifestReference{name: name, algorithm: method.SelectAttrValue("Algorithm", ""), digest: digest})
		}
		return entry, references, nil
	}
	return "", nil, nil
}

// checkManifest compares each file the signed manifest lists with its
// digest: the signature over the manifest proves nothing about a file whose
// bytes changed.
func checkManifest(unpacked container, references []manifestReference, report *domain.SignerReport) {
	for _, reference := range references {
		content, err := os.ReadFile(unpacked.file(reference.name))
		if err != nil {
			report.Integrity = domain.StatusBad
			report.Trust = domain.TrustBroken
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "signature.modified",
				Status:  domain.StatusBad,
				Message: "a file the signed manifest lists is missing from the container",
				Detail:  reference.name,
			})
			continue
		}
		digest, err := xmldsig.Digest(reference.algorithm, content)
		switch {
		case errors.Is(err, xmldsig.ErrUnverifiable):
			if report.Integrity == domain.StatusGood {
				report.Integrity = domain.StatusUnknown
			}
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "signature.unverifiable",
				Status:  domain.StatusUnknown,
				Message: "the manifest uses a digest trebaruna cannot check",
				Detail:  reference.name + ": " + err.Error(),
			})
		case !bytes.Equal(digest, reference.digest):
			report.Integrity = domain.StatusBad
			report.Trust = domain.TrustBroken
			report.Findings = append(report.Findings, domain.Finding{
				Code:    "signature.modified",
				Status:  domain.StatusBad,
				Message: "a file of the container does not match the digest the signed manifest gives",
				Detail:  reference.name,
			})
		}
	}
}

// file is where an entry was unpacked.
func (c container) file(name string) string {
	return filepath.Join(c.root, filepath.FromSlash(name))
}

// containerPath reads a reference to a file of a container: a relative path,
// escaped, that stays inside it.
func containerPath(uri string) (string, bool) {
	name, err := url.PathUnescape(uri)
	if err != nil || name == "" || strings.Contains(name, `\`) || strings.Contains(name, ":") {
		return "", false
	}
	cleaned := path.Clean(name)
	if path.IsAbs(cleaned) || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

// unpack reads the container into a private directory. The mimetype entry,
// stored first, says ASiC-S or ASiC-E; without one the suffix does. Entries
// whose names leave the container, or that exceed the size limit, are
// refused rather than skipped.
func unpack(archivePath string, odf bool) (container, error) {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return container{}, fmt.Errorf("open %q as a ZIP container: %w", archivePath, err)
	}
	defer archive.Close()

	unpacked := container{}
	switch strings.ToLower(filepath.Ext(archivePath)) {
	case ".asice", ".sce":
		unpacked.extended = true
	}
	if len(archive.File) > 0 && archive.File[0].Name == "mimetype" {
		mediaType, err := readEntry(archive.File[0], 256)
		if err != nil {
			return container{}, err
		}
		switch kind := strings.TrimSpace(string(mediaType)); {
		case odf && strings.HasPrefix(kind, "application/vnd.oasis.opendocument."):
			unpacked.extended = true
		case odf:
			return container{}, fmt.Errorf("%q is not an OpenDocument file: its mimetype is %q", archivePath, mediaType)
		case kind == asicSimpleMediaType:
			unpacked.extended = false
		case kind == asicExtendedMediaType:
			unpacked.extended = true
		default:
			return container{}, fmt.Errorf("%q is not an ASiC container: its mimetype is %q", archivePath, mediaType)
		}
	}

	if unpacked.root, err = os.MkdirTemp("", "trebaruna-asic-*"); err != nil {
		return container{}, err
	}
	if err := unpacked.fill(archive.File, archivePath); err != nil {
		os.RemoveAll(unpacked.root)
		return container{}, err
	}
	return unpacked, nil
}

// fill writes the entries under root and sorts them into documents and
// META-INF.
func (c *container) fill(entries []*zip.File, archivePath string) error {
	for _, entry := range entries {
		if entry.FileInfo().IsDir() {
			continue
		}
		name, inside := containerPath(entry.Name)
		if !inside || name != entry.Name {
			return fmt.Errorf("%q holds an entry named %q, outside the container", archivePath, entry.Name)
		}
		content, err := readEntry(entry, asicEntryLimit)
		if err != nil {
			return err
		}
		target := c.file(name)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			return err
		}
		// mimetype is unpacked, since an ODF signature covers it, but it is
		// the container's label, not one of its documents.
		switch {
		case name == "mimetype":
		case strings.HasPrefix(name, "META-INF/"):
			c.meta = append(c.meta, name)
		default:
			c.documents = append(c.documents, name)
		}
	}
	sort.Strings(c.meta)
	return nil
}

// readEntry reads an entry whole, refusing one larger than limit.
func readEntry(entry *zip.File, limit int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", entry.Name, err)
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", entry.Name, err)
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", entry.Name, limit)
	}
	return content, nil
}

// withoutFinding drops the findings with a code.
func withoutFinding(findings []domain.Finding, code string) []domain.Finding {
	kept := findings[:0]
	for _, finding := range findings {
		if finding.Code != code {
			kept = append(kept, finding)
		}
	}
	return kept
}
