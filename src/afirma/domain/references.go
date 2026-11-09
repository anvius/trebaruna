package domain

import (
	"fmt"
	"strconv"
	"strings"
)

// ReferencedDocument is a document an XAdES Externally Detached signature
// names by address and signs by a digest the page gives: trebaruna never
// sees the document.
type ReferencedDocument struct {
	URI    string
	Digest []byte
	// Algorithm is the digest's, as the page names it (SHA-512, a URI…).
	Algorithm string
	MimeType  string
}

// ExternallyDetached reports a request for references instead of content:
// useManifest=true, or the XAdES variant "XAdES Externally Detached".
func ExternallyDetached(properties map[string]string) bool {
	return UsesManifest(properties) || strings.EqualFold(strings.TrimSpace(properties["format"]), "XAdES Externally Detached")
}

// UsesManifest reports useManifest=true: the references go in a ds:Manifest.
func UsesManifest(properties map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(properties["useManifest"]), "true")
}

// References reads the documents as AutoFirma's XAdESSigner does: with uri,
// one document whose digest is the data; with useManifest and no uri,
// uri1, md1 (Base64) and mimeType1, uri2…, in order. AutoFirma takes the
// data as a digest even without precalculatedHashAlgorithm; the algorithm
// is that property, else referencesDigestMethod, else SHA-512.
func References(properties map[string]string, data []byte) ([]ReferencedDocument, error) {
	algorithm := "SHA-512"
	for _, named := range []string{properties["referencesDigestMethod"], properties["precalculatedHashAlgorithm"]} {
		if strings.TrimSpace(named) != "" {
			algorithm = strings.TrimSpace(named)
		}
	}
	if uri := strings.TrimSpace(properties["uri"]); uri != "" {
		return []ReferencedDocument{{URI: uri, Digest: data, Algorithm: algorithm, MimeType: properties["mimeType"]}}, nil
	}
	if !UsesManifest(properties) {
		return nil, Failure{Code: Params, Cause: "an externally detached signature needs the document's uri"}
	}
	var documents []ReferencedDocument
	for index := 1; ; index++ {
		suffix := strconv.Itoa(index)
		uri := strings.TrimSpace(properties["uri"+suffix])
		if uri == "" {
			break
		}
		digest, err := DecodeBase64(properties["md"+suffix])
		if err != nil || len(digest) == 0 {
			return nil, Failure{Code: Params, Cause: fmt.Sprintf("the digest of the manifest's reference %d (md%d)", index, index)}
		}
		documents = append(documents, ReferencedDocument{URI: uri, Digest: digest, Algorithm: algorithm, MimeType: properties["mimeType"+suffix]})
	}
	if len(documents) == 0 {
		return nil, Failure{Code: Params, Cause: "a manifest needs uri, or uri1 and md1"}
	}
	return documents, nil
}
