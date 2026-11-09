package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// SignDocument is the single use case of the signing slice.
//
// It reads the document, delegates to the adapter that matches the requested
// format, and writes the artefact. All decisions about *what* to produce live
// here; all decisions about *how* live in the adapters.
type SignDocument struct {
	files    FileStore
	clock    Clock
	identity IdentityResolver
	cades    CadesSigner
	pades    PadesSigner
	xades    XadesSigner
	// containers packs signatures into ASiC containers; nil without them.
	containers ContainerWriter
	// odf signs OpenDocument files inside themselves; nil without it.
	odf OdfSigner
}

// WithOdf lets the use case sign OpenDocument files.
func (u *SignDocument) WithOdf(odf OdfSigner) *SignDocument {
	u.odf = odf
	return u
}

// WithContainers lets the use case sign into ASiC containers.
func (u *SignDocument) WithContainers(containers ContainerWriter) *SignDocument {
	u.containers = containers
	return u
}

// NewSignDocument wires the use case. Every adapter is optional until used:
// a caller that only signs PDFs does not need an XAdES adapter.
func NewSignDocument(
	files FileStore, clock Clock, identity IdentityResolver,
	cades CadesSigner, pades PadesSigner, xades XadesSigner,
) *SignDocument {
	return &SignDocument{
		files: files, clock: clock, identity: identity,
		cades: cades, pades: pades, xades: xades,
	}
}

// Request describes one signature operation.
type Request struct {
	Document   domain.Document
	Format     domain.Format
	Level      domain.Level
	Signer     domain.Signer
	OutputPath string
	Placement  domain.SealPlacement
	Placements []domain.SealPlacement
	// Invisible signs a PDF without any mark on its pages. It excludes
	// Placement and Placements.
	Invisible bool
	// Detached leaves the document out of the signature, beside it: a CAdES
	// .p7s or a XAdES .xsig.
	Detached bool
	// Cosign adds a parallel signature to the envelope named by Document.
	Cosign bool
	// Countersign ("leaves" or "all") counter-signs the envelope's signatures.
	Countersign string
	// ContentPath is the document a detached envelope signs, to co-sign it.
	ContentPath string
	// Policy is the signature policy an EPES signature declares; zero for
	// none.
	Policy domain.SignaturePolicy
	// ClaimedRoles are the roles the signer claims (XAdES SignerRoleV2),
	// such as FacturaE's "emisor", its default.
	ClaimedRoles []string
	// SignedAt is the single instant used for both the stamp and the report, so
	// the document and the JSON cannot disagree about when it was signed.
	SignedAt        time.Time
	Reason          string
	Location        string
	TimestampURL    string
	TimestampUser   string
	TimestampSecret string
	// Enveloping carries the document inside a XAdES signature.
	Enveloping bool
	// Container packs the document and its detached signature into an ASiC
	// container; NoContainer writes the signature alone.
	Container domain.Container
	// MoreDocuments are the other documents of an ASiC-E container, signed
	// with Document by one signature.
	MoreDocuments []domain.Document
	// EmbedRevocation asks for PAdES B-LT: the signature plus a /DSS dictionary
	// carrying the status answers. It reaches the network, so it is opt-in.
	EmbedRevocation bool
}

// Execute performs the signature and returns the produced artefact.
func (u *SignDocument) Execute(ctx context.Context, request Request) (Artefact, error) {
	if err := u.validate(request); err != nil {
		return Artefact{}, err
	}

	content, err := u.files.Read(request.Document.Path())
	if err != nil {
		return Artefact{}, fmt.Errorf("read document %s: %w", request.Document.Path(), err)
	}

	identity := Identity{}
	if u.identity != nil {
		resolved, err := u.identity.Resolve(request.Signer)
		if err != nil {
			return Artefact{}, err
		}
		identity = resolved
	}

	output := request.OutputPath
	switch {
	case output != "":
	case request.Cosign:
		output = request.Document.AddedSignatureName("cosigned")
	case request.Countersign != "":
		output = request.Document.AddedSignatureName("countersigned")
	case request.Container != domain.NoContainer:
		output = request.Document.ContainerName(request.Container)
	case request.Detached:
		output = request.Document.DetachedSignatureName(request.Format)
	default:
		output = request.Document.SignedName(request.Format)
	}

	if err := request.Policy.AcceptsInvoice(content); err != nil {
		return Artefact{}, err
	}
	if request.Policy.IsFacturaE() {
		if request.ClaimedRoles, err = domain.FacturaERoles(request.ClaimedRoles); err != nil {
			return Artefact{}, err
		}
	}

	// The instant is captured once and reused: two calls to the clock can land on
	// different seconds, which makes the report disagree with the stamp.
	signedAt := u.clock.Now()

	var signed []byte
	if request.Container == domain.ASiCE {
		signed, err = u.signExtended(ctx, request.WithSignedAt(signedAt), content)
	} else {
		signed, err = u.sign(ctx, request.WithSignedAt(signedAt), content)
	}
	if err != nil {
		return Artefact{}, err
	}
	if request.Container == domain.ASiCS {
		signed, err = u.containers.WriteContainer(request.Container, []ContainerEntry{
			{Name: request.Document.Name(), Content: content},
			{Name: request.Container.SignatureEntry(request.Format), Content: signed},
		})
		if err != nil {
			return Artefact{}, fmt.Errorf("pack the %s container: %w", request.Container, err)
		}
	}

	if err := u.files.Write(output, signed); err != nil {
		return Artefact{}, fmt.Errorf("write signed document %s: %w", output, err)
	}

	return Artefact{
		Path:       output,
		Format:     request.Format,
		Level:      request.Level,
		Size:       len(signed),
		SignedAt:   signedAt,
		SignerName: request.Signer.NameFor(identity.Holder),
		// Only a PDF carries a visible seal: reporting one for CAdES or XAdES
		// would be a lie the caller could act on.
		SealCount:      sealCount(request),
		HasSeal:        sealCount(request) > 0,
		SelfSigned:     identity.SelfSigned,
		DocumentDigest: fingerprint(content),
		SignedDigest:   fingerprint(signed),
		KeySource:      request.Signer.KeySource(),
		RemoteService:  remoteHost(request.Signer),
	}, nil
}

// remoteHost names the provider of a remote key; empty for any other.
func remoteHost(signer domain.Signer) string {
	if signer.KeySource() != domain.FromRemote {
		return ""
	}
	return signer.Remote().Host()
}

// fingerprint is the SHA-256 of a byte string in lower-case hex.
func fingerprint(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

// detached reports a signature kept apart from the document: asked for, or
// going into a container beside it.
func (r Request) detached() bool {
	return r.Detached || r.Container != domain.NoContainer
}

// xmlPackaging is how a XAdES signature holds the document, from the flags.
func (r Request) xmlPackaging() domain.XMLPackaging {
	switch {
	case r.detached():
		return domain.XMLDetached
	case r.Enveloping:
		return domain.XMLEnveloping
	}
	return domain.XMLEnveloped
}

// validate applies guard clauses so the adapters receive a coherent request.
func (u *SignDocument) validate(request Request) error {
	if request.detached() && request.Enveloping {
		return fmt.Errorf("a signature is either detached or enveloping; choose one")
	}
	if err := u.validateContainer(request); err != nil {
		return err
	}
	// Only an enveloped XML signature needs an XML document: detached and
	// enveloping ones sign any file.
	anyFile := request.Format.IsXML() && !request.xmlPackaging().NeedsXML()
	if !request.Document.Supports(request.Format) && !anyFile {
		return fmt.Errorf("%w: %s cannot hold a %s signature",
			domain.ErrUnsupportedFormat, request.Document.Extension(), request.Format)
	}

	if request.Level.NeedsTimestamp() && request.TimestampURL == "" {
		return fmt.Errorf("level %s needs a timestamp authority: pass --tsa <url>", request.Level)
	}
	if request.Cosign && request.Countersign != "" {
		return fmt.Errorf("co-signing and counter-signing are separate operations; choose one")
	}
	if request.Policy.IsFacturaE() && (request.Format != domain.Xades || request.xmlPackaging() != domain.XMLEnveloped) {
		return fmt.Errorf("%w: they are XAdES enveloped signatures", domain.ErrNotFacturaE)
	}
	if err := request.Policy.FitsFormat(request.Format); err != nil {
		return err
	}
	if len(request.ClaimedRoles) > 0 && request.Format != domain.Xades && request.Format != domain.Odf {
		return fmt.Errorf("a claimed role goes in XAdES signatures, not %s", request.Format)
	}
	if (request.Cosign || request.Countersign != "") && request.Format != domain.Cades {
		return fmt.Errorf("signatures are added to CAdES envelopes (.p7m, .p7s); %s is signed again by signing the signed file", request.Format)
	}
	if request.Countersign != "" && request.Countersign != "leaves" && request.Countersign != "all" {
		return fmt.Errorf("--countersign takes leaves or all, not %q", request.Countersign)
	}
	if (request.Cosign || request.Countersign != "") && request.Level.EmbedsRevocation() {
		return fmt.Errorf("signatures added to an envelope support levels B and T; %s is not available for them yet", request.Level)
	}
	if request.Detached && request.Format != domain.Cades && !request.Format.IsXML() {
		return fmt.Errorf("only CAdES and XML signatures can be detached; %s carries its signature inside the document", request.Format)
	}
	if request.Enveloping && !request.Format.IsXML() {
		return fmt.Errorf("only XML signatures can be enveloping, not %s", request.Format)
	}
	if request.Format == domain.Xmldsig && request.Level != domain.BES {
		return fmt.Errorf("XMLDSig signatures have no properties to hold a timestamp; level %s needs XAdES", request.Level)
	}
	if request.Invisible && (len(request.Placements) > 0 || !request.Placement.IsZero()) {
		return fmt.Errorf("an invisible signature cannot also place a seal")
	}

	switch request.Format {
	case domain.Cades:
		if u.cades == nil {
			return fmt.Errorf("no CAdES adapter configured")
		}
	case domain.Pades:
		if u.pades == nil {
			return fmt.Errorf("no PAdES adapter configured")
		}
	case domain.Xades, domain.Xmldsig:
		if u.xades == nil {
			return fmt.Errorf("no XML signature adapter configured")
		}
	case domain.Odf:
		if u.odf == nil {
			return fmt.Errorf("no OpenDocument adapter configured")
		}
		if request.detached() || request.Enveloping || request.Cosign || request.Countersign != "" {
			return fmt.Errorf("an OpenDocument file is signed inside itself; sign the signed file again to add a signature")
		}
	default:
		return fmt.Errorf("%w: %q", domain.ErrUnsupportedFormat, request.Format)
	}

	return nil
}

// validateContainer applies the container's rules: CAdES or XML signatures,
// detached, and the signature is new (signatures are added to a container
// by signing its document again).
func (u *SignDocument) validateContainer(request Request) error {
	switch {
	case request.Container == domain.NoContainer && len(request.MoreDocuments) > 0:
		return fmt.Errorf("several documents under one signature go into an ASiC-E container")
	case request.Container == domain.NoContainer:
		return nil
	case request.Container == domain.ASiCS && len(request.MoreDocuments) > 0:
		return fmt.Errorf("an ASiC-S container holds one document; several go into ASiC-E")
	case u.containers == nil:
		return fmt.Errorf("no container writer configured")
	case !request.Container.Holds(request.Format):
		return fmt.Errorf("an ASiC container holds CAdES or XML signatures; %s signs inside the document", request.Format)
	case request.Cosign || request.Countersign != "":
		return fmt.Errorf("signatures are added to a container's document by signing it again, not by --cosign or --countersign")
	}
	names := map[string]bool{request.Document.Name(): true}
	for _, other := range request.MoreDocuments {
		if names[other.Name()] {
			return fmt.Errorf("two documents are named %s; a container holds each name once", other.Name())
		}
		names[other.Name()] = true
	}
	return nil
}

// sign dispatches to the adapter that owns the format.
//
// The second return value reports whether the signing certificate is
// self-signed. Callers must surface it: a self-signed signature is valid
// cryptography but carries no third-party trust, and hiding that would mislead.
func (u *SignDocument) sign(ctx context.Context, request Request, content []byte) ([]byte, error) {
	switch request.Format {
	case domain.Cades:
		return u.cades.SignCades(ctx, u.cadesRequest(request, content))

	case domain.Pades:
		signed, err := u.pades.SignPades(ctx, PadesRequest{
			Content:         content,
			Signer:          request.Signer,
			Level:           request.Level,
			EmbedRevocation: request.EmbedRevocation,
			Placement:       request.Placement,
			Placements:      sealPlacements(request),
			SignedAt:        request.SignedAt,
			Reason:          request.Reason,
			Location:        request.Location,
			TimestampURL:    request.TimestampURL,
			TimestampUser:   request.TimestampUser,
			TimestampSecret: request.TimestampSecret,
			Policy:          request.Policy,
		})
		return signed, err

	case domain.Xades, domain.Xmldsig:
		return u.xades.SignXades(ctx, u.xadesRequest(request, content))
	case domain.Odf:
		return u.odf.SignOdf(ctx, u.xadesRequest(request, content))
	}

	return nil, fmt.Errorf("%w: %q", domain.ErrUnsupportedFormat, request.Format)
}

// cadesRequest is what the CAdES adapter needs to sign content.
func (u *SignDocument) cadesRequest(request Request, content []byte) CadesRequest {
	return CadesRequest{
		Content:         content,
		Detached:        request.detached(),
		Cosign:          request.Cosign,
		Countersign:     request.Countersign,
		DetachedContent: u.detachedContent(request),
		Signer:          request.Signer,
		Level:           request.Level,
		EmbedRevocation: request.EmbedRevocation,
		TimestampURL:    request.TimestampURL,
		TimestampUser:   request.TimestampUser,
		TimestampSecret: request.TimestampSecret,
		Policy:          request.Policy,
	}
}

// xadesRequest is what the XML adapter needs to sign content.
func (u *SignDocument) xadesRequest(request Request, content []byte) XadesRequest {
	return XadesRequest{
		Plain:           request.Format == domain.Xmldsig,
		Content:         content,
		Signer:          request.Signer,
		Level:           request.Level,
		EmbedRevocation: request.EmbedRevocation,
		Packaging:       request.xmlPackaging(),
		DocumentName:    request.Document.Name(),
		InASiC:          request.Container != domain.NoContainer,
		TimestampURL:    request.TimestampURL,
		TimestampUser:   request.TimestampUser,
		TimestampSecret: request.TimestampSecret,
		Policy:          request.Policy,
		ClaimedRoles:    request.ClaimedRoles,
	}
}

// signExtended signs several documents into an ASiC-E container (ETSI EN
// 319 162-1): one XML signature that references each of them, or a CAdES
// signature over an ASiCManifest listing their digests.
func (u *SignDocument) signExtended(ctx context.Context, request Request, content []byte) ([]byte, error) {
	documents := []ContainerEntry{{Name: request.Document.Name(), Content: content}}
	for _, other := range request.MoreDocuments {
		data, err := u.files.Read(other.Path())
		if err != nil {
			return nil, fmt.Errorf("read document %s: %w", other.Path(), err)
		}
		documents = append(documents, ContainerEntry{Name: other.Name(), Content: data})
	}
	entries := append([]ContainerEntry{}, documents...)
	signatureEntry := request.Container.SignatureEntry(request.Format)

	if request.Format.IsXML() {
		signing := u.xadesRequest(request, content)
		for _, other := range documents[1:] {
			signing.MoreDocuments = append(signing.MoreDocuments, DetachedDocument{Name: other.Name, Content: other.Content})
		}
		signed, err := u.xades.SignXades(ctx, signing)
		if err != nil {
			return nil, err
		}
		entries = append(entries, ContainerEntry{Name: signatureEntry, Content: signed})
		return u.containers.WriteContainer(request.Container, entries)
	}

	manifest, err := u.containers.Manifest(signatureEntry, documents)
	if err != nil {
		return nil, err
	}
	signed, err := u.cades.SignCades(ctx, u.cadesRequest(request, manifest))
	if err != nil {
		return nil, err
	}
	entries = append(entries,
		ContainerEntry{Name: domain.ManifestEntry, Content: manifest},
		ContainerEntry{Name: signatureEntry, Content: signed})
	return u.containers.WriteContainer(request.Container, entries)
}

// SystemClock is the production Clock.
type SystemClock struct{}

// Now returns the current local time.
func (SystemClock) Now() time.Time { return time.Now() }

// detachedContent reads the document a detached envelope signs, when the
// caller named one for a co-signature. Errors surface in the adapter, which
// then reports the missing document.
func (u *SignDocument) detachedContent(request Request) []byte {
	if !request.Cosign || request.ContentPath == "" {
		return nil
	}
	content, err := u.files.Read(request.ContentPath)
	if err != nil {
		return nil
	}
	return content
}

// sealPlacements returns the stamps to draw, folding the single-placement field
// into the list so callers of the old shape keep working.
func sealPlacements(request Request) []domain.SealPlacement {
	if request.Invisible {
		return nil
	}
	if len(request.Placements) > 0 {
		return request.Placements
	}
	if request.Placement.IsZero() {
		return nil
	}
	return []domain.SealPlacement{request.Placement}
}

// sealCount reports how many visible marks the artefact carries.
func sealCount(request Request) int {
	if request.Format != domain.Pades {
		return 0
	}
	return len(sealPlacements(request))
}

// WithSignedAt returns a copy carrying the signing instant.
func (r Request) WithSignedAt(moment time.Time) Request {
	r.SignedAt = moment
	return r
}
