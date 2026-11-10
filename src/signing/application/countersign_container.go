package application

import (
	"context"
	"fmt"
	"path"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// countersignContainer counter-signs a container through CountersignContainer.
func (u *SignDocument) countersignContainer(ctx context.Context, request Request, content []byte) (SignedContainer, error) {
	if u.containers == nil {
		return SignedContainer{}, fmt.Errorf("no container adapter configured")
	}
	return NewCountersignContainer(u.containers, u.cades, u.xades).Execute(ctx, request, content)
}

// CountersignContainer is the use case that counter-signs the signatures of
// an ASiC container where they are (ETSI EN 319 162-1 keeps each in its
// file): a CAdES signature file takes CMS counter-signatures over the
// values of the signatures chosen (RFC 5652, 11.4), a XAdES signatures
// file XAdES counter-signatures inside them. The request's scope, leaves
// or all, applies in every signature file. It works on the container's
// bytes: signing a file and answering a web page share it.
type CountersignContainer struct {
	containers ContainerWriter
	cades      CadesSigner
	xades      XadesSigner
}

// NewCountersignContainer wires the use case.
func NewCountersignContainer(containers ContainerWriter, cades CadesSigner, xades XadesSigner) *CountersignContainer {
	return &CountersignContainer{containers: containers, cades: cades, xades: xades}
}

// Execute returns the container with its signatures counter-signed; the
// request's document is not read, the container is.
func (u *CountersignContainer) Execute(ctx context.Context, request Request, content []byte) (SignedContainer, error) {
	container, entries, err := u.containers.ReadContainer(content)
	if err != nil {
		return SignedContainer{}, err
	}
	var documents []ContainerEntry
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name, "META-INF/") {
			documents = append(documents, entry)
		}
	}

	var format domain.Format
	for index, entry := range entries {
		base := strings.ToLower(path.Base(entry.Name))
		var countersigned []byte
		switch {
		case !strings.HasPrefix(entry.Name, "META-INF/"):
			continue
		case strings.HasPrefix(base, "signature") && strings.HasSuffix(base, ".p7s"):
			signing := containerCades(request, entry.Content)
			signing.Countersign, signing.DetachedContent = request.Countersign, u.signedBy(container, entry.Name, entries, documents)
			countersigned, err = u.cades.SignCades(ctx, signing)
			format = firstFormat(format, domain.Cades)
		case strings.Contains(base, "signatures") && strings.HasSuffix(base, ".xml"):
			countersigned, err = u.xades.SignXades(ctx, XadesRequest{Content: entry.Content, Countersign: request.Countersign,
				Packaging: domain.XMLEnveloped, Signer: request.Signer, Level: request.Level, EmbedRevocation: request.EmbedRevocation,
				TimestampURL: request.TimestampURL, TimestampUser: request.TimestampUser, TimestampSecret: request.TimestampSecret,
				Policy: request.Policy, ClaimedRoles: request.ClaimedRoles, Place: domain.ProductionPlace{City: request.Location}})
			format = firstFormat(format, domain.Xades)
		default:
			continue
		}
		if err != nil {
			return SignedContainer{}, fmt.Errorf("%s: %w", entry.Name, err)
		}
		entries[index].Content = countersigned
	}
	if format == "" {
		return SignedContainer{}, fmt.Errorf("the container holds no CAdES or XAdES signature to counter-sign")
	}
	written, err := u.containers.WriteContainer(container, entries)
	if err != nil {
		return SignedContainer{}, err
	}
	return SignedContainer{Content: written, Format: format}, nil
}

// signedBy is what a CAdES signature file of the container signs, for the
// archive timestamp that seals a counter-signature: an ASiC-S's document,
// or the ASiCManifest that names the signature in an ASiC-E.
func (u *CountersignContainer) signedBy(container domain.Container, signature string, entries, documents []ContainerEntry) []byte {
	if container == domain.ASiCS && len(documents) > 0 {
		return documents[0].Content
	}
	manifest, _ := u.containers.ManifestOf(signature, entries)
	return manifest.Content
}

// firstFormat keeps the kind found first, the one the report names.
func firstFormat(found, format domain.Format) domain.Format {
	if found != "" {
		return found
	}
	return format
}
