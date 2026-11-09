// Package application orchestrates signing. It defines the ports the
// infrastructure must satisfy; it never imports an adapter.
package application

import (
	"context"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// Artefact is the result of a successful signature.
type Artefact struct {
	Path       string
	Format     domain.Format
	Level      domain.Level
	Size       int
	SignedAt   time.Time
	SignerName string
	HasSeal    bool
	// SealCount is how many visible marks the artefact carries.
	SealCount  int
	SelfSigned bool
	// DocumentDigest and SignedDigest are the SHA-256 of what was signed and of
	// what was written, in lower-case hex: the receipt a person can compare.
	DocumentDigest string
	SignedDigest   string
	// KeySource says where the key was; RemoteService names the provider of
	// a remote key, so a remote signature says so (ADR-0014).
	KeySource     domain.KeySource
	RemoteService string
}

// KeyMaterial is what the infrastructure resolved from a Signer.
//
// It is deliberately opaque: the application does not know whether the key
// sits in a file or behind a smartcard, only that it can sign bytes.
type KeyMaterial struct {
	CertificateChain [][]byte
	SignerName       string
	SelfSigned       bool
}

// CadesSigner produces a CMS container (.p7m) from raw content.
type CadesSigner interface {
	SignCades(ctx context.Context, request CadesRequest) ([]byte, error)
}

// CadesRequest carries everything a CMS adapter needs.
type CadesRequest struct {
	Content []byte
	// Detached leaves the content out of the container (.p7s): the signature
	// travels beside the document instead of wrapping it.
	Detached bool
	// Cosign adds a parallel signature to the envelope in Content.
	Cosign bool
	// Countersign, "leaves" or "all", counter-signs signatures of the envelope
	// in Content.
	Countersign string
	// DetachedContent is the document a detached envelope signs, needed to
	// co-sign it.
	DetachedContent []byte
	Signer          domain.Signer
	Level           domain.Level
	TimestampURL    string
	TimestampUser   string
	TimestampSecret string
	// EmbedRevocation asks for CAdES-LT: revocation material attached beside the
	// signature. It needs a live status source, so it is opt-in.
	EmbedRevocation bool
	// Policy is the signature policy declared in the signed attributes.
	Policy domain.SignaturePolicy
}

// PadesSigner produces a signed PDF.
type PadesSigner interface {
	SignPades(ctx context.Context, request PadesRequest) ([]byte, error)
}

// PadesRequest carries everything a PDF adapter needs.
type PadesRequest struct {
	Content   []byte
	Signer    domain.Signer
	Level     domain.Level
	Placement domain.SealPlacement
	// Placements carries every stamp for the same signature. A signature can
	// carry several marks (one per page, or a rubric plus a full stamp) but
	// only holds one signing key, so they share a single cryptographic value.
	Placements []domain.SealPlacement
	// Rubric is drawn in each seal beside the certificate data.
	Rubric domain.Rubric
	// SignedAt is the single instant used for both the stamp and the report, so
	// the document and the JSON cannot disagree about when it was signed.
	SignedAt        time.Time
	Reason          string
	Location        string
	TimestampURL    string
	TimestampUser   string
	TimestampSecret string
	// EmbedRevocation asks for a /DSS dictionary. It needs a live status source,
	// so it is opt-in: signing must not reach the network unasked.
	EmbedRevocation bool
	// Policy is the signature policy declared in the signed attributes.
	Policy domain.SignaturePolicy
	// Field is the document's empty signature field to sign in, by its
	// fully qualified name; empty adds a field. The seal goes in its box
	// unless Invisible.
	Field     string
	Invisible bool
}

// XadesSigner produces a signed XML document.
type XadesSigner interface {
	SignXades(ctx context.Context, request XadesRequest) ([]byte, error)
}

// XadesRequest carries everything an XML adapter needs.
type XadesRequest struct {
	// Place is the production place the signature declares.
	Place domain.ProductionPlace
	// Countersign ("leaves" or "all") counter-signs the XAdES signatures of
	// the signed document in Content instead of signing it.
	Countersign string
	Content     []byte
	Signer      domain.Signer
	Level       domain.Level
	// Packaging is how the signature holds Content; empty is enveloped.
	Packaging domain.XMLPackaging
	// Plain writes an XMLDSig signature: no XAdES properties, so level B
	// only, without policy or roles.
	Plain bool
	// DocumentName names the document a detached signature references;
	// DocumentCanonical digests its XML canonical form (DetachedDocument).
	DocumentName      string
	DocumentCanonical bool
	// InASiC writes a detached signature inside asic:XAdESSignatures, as an
	// ASiC container's META-INF/signatures.xml holds it.
	InASiC bool
	// MoreDocuments are other documents a detached signature references,
	// after Content (ASiC-E, ODF).
	MoreDocuments []DetachedDocument
	// Holder is an XML document whose root receives the detached signature
	// as its last child: ODF's documentsignatures.xml, new or with earlier
	// signatures. The signature is made inside it, because the namespaces
	// it declares are part of what the signature covers.
	Holder          []byte
	TimestampURL    string
	TimestampUser   string
	TimestampSecret string
	// EmbedRevocation asks for XAdES-LT: revocation material inside the
	// signature. It needs a live status source, so it is opt-in.
	EmbedRevocation bool
	// Policy is the signature policy declared in the signed properties.
	Policy domain.SignaturePolicy
	// ClaimedRoles are the roles the signer claims (SignerRoleV2).
	ClaimedRoles []string
}

// OdfSigner signs an OpenDocument package inside itself; request.Content
// is the package, the rest says how to sign.
type OdfSigner interface {
	SignOdf(ctx context.Context, request XadesRequest) ([]byte, error)
}

// OoxmlSigner signs an Office Open XML package (.docx, .xlsx, .pptx)
// inside itself; request.Content is the package.
type OoxmlSigner interface {
	SignOoxml(ctx context.Context, request XadesRequest) ([]byte, error)
}

// ContainerWriter packs documents and their signatures into an ASiC
// container, and writes the ASiCManifest a CAdES signature of an ASiC-E
// covers.
type ContainerWriter interface {
	WriteContainer(container domain.Container, entries []ContainerEntry) ([]byte, error)
	Manifest(signatureEntry string, documents []ContainerEntry) ([]byte, error)
	// ReadContainer opens a container: its kind and its files but the
	// mimetype.
	ReadContainer(content []byte) (domain.Container, []ContainerEntry, error)
	// AddXMLSignatures puts the signatures of added into the signatures
	// file of an ASiC-S, its references resolved from files; every
	// signature that verified must still verify.
	AddXMLSignatures(signatures, added []byte, files []ContainerEntry) ([]byte, error)
}

// ContainerEntry is a file of a container, by its path inside it.
type ContainerEntry struct {
	Name    string
	Content []byte
}

// DetachedDocument is a document a detached signature references by name.
// Canonical asks for its XML canonical form to be digested, not its bytes,
// as ODF signs the XML streams of a package.
type DetachedDocument struct {
	Name      string
	Content   []byte
	Canonical bool
}

// FileStore writes the produced artefact.
type FileStore interface {
	Read(path string) ([]byte, error)
	Write(path string, content []byte) error
}

// Clock reports the current time so tests can freeze it.
type Clock interface {
	Now() time.Time
}

// Identity describes the certificate a signer will use, without signing.
//
// It exists so the use case can report trust facts (self-signed, subject,
// issuer) before and after signing, instead of hiding them inside an adapter.
type Identity struct {
	// Holder is the name printed on the certificate, for signers nobody named.
	Holder     string
	Subject    string
	Issuer     string
	SelfSigned bool
	KeySource  domain.KeySource
}

// IdentityResolver reads the certificate behind a signer.
type IdentityResolver interface {
	Resolve(signer domain.Signer) (Identity, error)
}
