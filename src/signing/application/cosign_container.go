package application

import (
	"context"
	"fmt"
	"path"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// cosignContainer adds a parallel signature to an ASiC container, of the
// kind it already holds (ETSI EN 319 162-1): an ASiC-S's CAdES signature
// is co-signed in place, its XAdES signatures file takes one more; an
// ASiC-E takes a new signature file over all its documents (a CAdES one
// over a new ASiCManifest, or a XAdES one).
func (u *SignDocument) cosignContainer(ctx context.Context, request Request, content []byte) ([]byte, error) {
	if u.containers == nil {
		return nil, fmt.Errorf("no container adapter configured")
	}
	container, entries, err := u.containers.ReadContainer(content)
	if err != nil {
		return nil, err
	}
	var documents []ContainerEntry
	cades, xades := -1, -1
	for index, entry := range entries {
		base := strings.ToLower(path.Base(entry.Name))
		switch {
		case !strings.HasPrefix(entry.Name, "META-INF/"):
			documents = append(documents, entry)
		case cades < 0 && strings.HasPrefix(base, "signature") && strings.HasSuffix(base, ".p7s"):
			cades = index
		case xades < 0 && strings.Contains(base, "signatures") && strings.HasSuffix(base, ".xml"):
			xades = index
		}
	}
	if len(documents) == 0 {
		return nil, fmt.Errorf("the container holds no document to co-sign")
	}

	switch {
	case container == domain.ASiCS && cades >= 0:
		cosigning := containerCades(request, entries[cades].Content)
		cosigning.Cosign, cosigning.DetachedContent = true, documents[0].Content
		cosigned, err := u.cades.SignCades(ctx, cosigning)
		if err != nil {
			return nil, err
		}
		entries[cades].Content = cosigned
	case container == domain.ASiCS && xades >= 0:
		added, err := u.xades.SignXades(ctx, u.containerXades(request, documents))
		if err != nil {
			return nil, err
		}
		merged, err := u.containers.AddXMLSignatures(entries[xades].Content, added, documents)
		if err != nil {
			return nil, err
		}
		entries[xades].Content = merged
	case container == domain.ASiCE && xades >= 0:
		added, err := u.xades.SignXades(ctx, u.containerXades(request, documents))
		if err != nil {
			return nil, err
		}
		entries = append(entries, ContainerEntry{Name: freeEntry(entries, "META-INF/signatures%03d.xml"), Content: added})
	case container == domain.ASiCE && cades >= 0:
		signatureEntry := freeEntry(entries, "META-INF/signature%03d.p7s")
		manifest, err := u.containers.Manifest(signatureEntry, documents)
		if err != nil {
			return nil, err
		}
		signing := containerCades(request, manifest)
		signing.Detached = true
		signed, err := u.cades.SignCades(ctx, signing)
		if err != nil {
			return nil, err
		}
		entries = append(entries,
			ContainerEntry{Name: freeEntry(entries, "META-INF/ASiCManifest%03d.xml"), Content: manifest},
			ContainerEntry{Name: signatureEntry, Content: signed})
	default:
		return nil, fmt.Errorf("the container holds no CAdES or XAdES signature to co-sign")
	}
	return u.containers.WriteContainer(container, entries)
}

// containerCades is a CAdES signature over content for a container.
func containerCades(request Request, content []byte) CadesRequest {
	return CadesRequest{Content: content, Signer: request.Signer, Level: request.Level,
		EmbedRevocation: request.EmbedRevocation, TimestampURL: request.TimestampURL,
		TimestampUser: request.TimestampUser, TimestampSecret: request.TimestampSecret, Policy: request.Policy}
}

// containerXades is the detached XAdES signature over a container's
// documents, in an asic:XAdESSignatures file.
func (u *SignDocument) containerXades(request Request, documents []ContainerEntry) XadesRequest {
	signing := XadesRequest{Content: documents[0].Content, DocumentName: documents[0].Name, InASiC: true,
		Packaging: domain.XMLDetached, Signer: request.Signer, Level: request.Level, EmbedRevocation: request.EmbedRevocation,
		TimestampURL: request.TimestampURL, TimestampUser: request.TimestampUser, TimestampSecret: request.TimestampSecret,
		Policy: request.Policy, ClaimedRoles: request.ClaimedRoles, Place: domain.ProductionPlace{City: request.Location}}
	for _, other := range documents[1:] {
		signing.MoreDocuments = append(signing.MoreDocuments, DetachedDocument{Name: other.Name, Content: other.Content})
	}
	return signing
}

// freeEntry is the first name the pattern gives, from 2, the container
// does not hold yet.
func freeEntry(entries []ContainerEntry, pattern string) string {
	taken := map[string]bool{}
	for _, entry := range entries {
		taken[entry.Name] = true
	}
	for number := 2; ; number++ {
		if name := fmt.Sprintf(pattern, number); !taken[name] {
			return name
		}
	}
}
