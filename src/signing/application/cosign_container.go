package application

import (
	"context"
	"fmt"
	"path"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// cosignContainer co-signs a container through CosignContainer.
func (u *SignDocument) cosignContainer(ctx context.Context, request Request, content []byte) (SignedContainer, error) {
	if u.containers == nil {
		return SignedContainer{}, fmt.Errorf("no container adapter configured")
	}
	return NewCosignContainer(u.containers, u.cades, u.xades).Execute(ctx, request, content)
}

// SignedContainer is the container with signatures added, and their
// format: the kind the container held, whatever the request asked.
type SignedContainer struct {
	Content []byte
	Format  domain.Format
}

// CosignContainer is the use case that adds a parallel signature to an
// ASiC container, of the kind it already holds (ETSI EN 319 162-1): an
// ASiC-S's CAdES signature is co-signed in place, its XAdES signatures
// file takes one more; an ASiC-E takes a new signature file over all its
// documents (a CAdES one over a new ASiCManifest, or a XAdES one). It
// works on the container's bytes: signing a file and answering a web page
// share it.
type CosignContainer struct {
	containers ContainerWriter
	cades      CadesSigner
	xades      XadesSigner
}

// NewCosignContainer wires the use case.
func NewCosignContainer(containers ContainerWriter, cades CadesSigner, xades XadesSigner) *CosignContainer {
	return &CosignContainer{containers: containers, cades: cades, xades: xades}
}

// Execute returns the container with the request's signature added; the
// request's document is not read, the container is.
func (u *CosignContainer) Execute(ctx context.Context, request Request, content []byte) (SignedContainer, error) {
	container, entries, err := u.containers.ReadContainer(content)
	if err != nil {
		return SignedContainer{}, err
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
		return SignedContainer{}, fmt.Errorf("the container holds no document to co-sign")
	}
	entries, format, err := u.addSignature(ctx, request, container, entries, documents, cades, xades)
	if err != nil {
		return SignedContainer{}, err
	}
	written, err := u.containers.WriteContainer(container, entries)
	if err != nil {
		return SignedContainer{}, err
	}
	return SignedContainer{Content: written, Format: format}, nil
}

// addSignature adds the parallel signature to the entries, of the kind the
// container holds (cades and xades index its first signature of each kind,
// -1 for none), and names that kind.
func (u *CosignContainer) addSignature(ctx context.Context, request Request, container domain.Container, entries, documents []ContainerEntry,
	cades, xades int) ([]ContainerEntry, domain.Format, error) {
	switch {
	case container == domain.ASiCS && cades >= 0:
		cosigning := containerCades(request, entries[cades].Content)
		cosigning.Cosign, cosigning.DetachedContent = true, documents[0].Content
		cosigned, err := u.cades.SignCades(ctx, cosigning)
		if err != nil {
			return nil, "", err
		}
		entries[cades].Content = cosigned
		return entries, domain.Cades, nil
	case container == domain.ASiCS && xades >= 0:
		added, err := u.xades.SignXades(ctx, containerXades(request, documents))
		if err != nil {
			return nil, "", err
		}
		merged, err := u.containers.AddXMLSignatures(entries[xades].Content, added, documents)
		if err != nil {
			return nil, "", err
		}
		entries[xades].Content = merged
		return entries, domain.Xades, nil
	case container == domain.ASiCE && xades >= 0:
		added, err := u.xades.SignXades(ctx, containerXades(request, documents))
		if err != nil {
			return nil, "", err
		}
		return append(entries, ContainerEntry{Name: freeEntry(entries, "META-INF/signatures%03d.xml"), Content: added}), domain.Xades, nil
	case container == domain.ASiCE && cades >= 0:
		signatureEntry := freeEntry(entries, "META-INF/signature%03d.p7s")
		manifest, err := u.containers.Manifest(signatureEntry, documents)
		if err != nil {
			return nil, "", err
		}
		signing := containerCades(request, manifest)
		signing.Detached = true
		signed, err := u.cades.SignCades(ctx, signing)
		if err != nil {
			return nil, "", err
		}
		return append(entries,
			ContainerEntry{Name: freeEntry(entries, "META-INF/ASiCManifest%03d.xml"), Content: manifest},
			ContainerEntry{Name: signatureEntry, Content: signed}), domain.Cades, nil
	}
	return nil, "", fmt.Errorf("the container holds no CAdES or XAdES signature to co-sign")
}

// containerCades is a CAdES signature over content for a container.
func containerCades(request Request, content []byte) CadesRequest {
	return CadesRequest{Content: content, Signer: request.Signer, Level: request.Level,
		EmbedRevocation: request.EmbedRevocation, TimestampURL: request.TimestampURL,
		TimestampUser: request.TimestampUser, TimestampSecret: request.TimestampSecret, Policy: request.Policy}
}

// containerXades is the detached XAdES signature over a container's
// documents, in an asic:XAdESSignatures file.
func containerXades(request Request, documents []ContainerEntry) XadesRequest {
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
