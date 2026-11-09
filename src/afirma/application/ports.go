// Package application answers afirma:// requests: read, show to a person,
// do what was approved, and send the answer back the way the page waits for
// it.
package application

import (
	"context"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// Proposal is what the person sees before anything is signed or sent: who
// asks, for what, over which data, which certificates the page accepts, and
// the weaknesses the protocol imposes.
type Proposal struct {
	Operation domain.Operation
	// Site is the host the answer goes to; AppName is what the page calls
	// itself, which it chooses freely.
	Site    string
	AppName string
	Format  string
	// Data describes what is signed or saved.
	DataSize   int
	DataSHA256 string
	DataURL    string
	ChooseFile bool
	// SuggestedName is the file name the page proposes for save and
	// signandsave.
	SuggestedName string
	// Items are the documents of a batch.
	Items []domain.BatchItem
	// Rejected says why the last certificate chosen was refused, when the
	// person is asked again.
	Rejected string
	Filter   domain.CertificateFilter
	Warnings []string
	// Policy, Roles and Place are what the page asks the signature to
	// declare of itself.
	Policy string
	Roles  []string
	Place  string
	// Remembered names the holder of the key the page asked to keep at an
	// earlier request (sticky): the person may approve with it again
	// without choosing it.
	Remembered string
	// keep is the page's sticky: the key approved now is kept.
	keep bool
	// PlaceSeal is the page's visibleSignature, "want" or "optional": the
	// person places the seal on SealDocument, the PDF the page sent.
	PlaceSeal    string
	SealDocument []byte
}

// Decision is the person's answer: approved, with the key to use.
type Decision struct {
	Approved bool
	Key      signing.Signer
	// File is the file chosen when the page sent no data.
	File []byte
	// FileName is its name, which the answer reports from protocol 3 on.
	FileName string
	// SavePath is where save and signandsave write, chosen by the person.
	SavePath string
	// UseRemembered approves with the key kept from the page's earlier
	// request, which Proposal.Remembered names, instead of Key.
	UseRemembered bool
	// Seal is where the person placed the seal, when asked to.
	Seal domain.SealBox
}

// Approver shows a proposal to the person and returns their decision.
type Approver interface {
	Approve(ctx context.Context, proposal Proposal) (Decision, error)
}

// PageSignature is a signature a page asked for, once approved.
type PageSignature struct {
	Crypto     domain.Operation
	Format     domain.Format
	Algorithm  string
	Properties map[string]string
	Data       []byte
	Key        signing.Signer
}

// Signed is the certificate that signed and the signature file.
type Signed struct {
	Certificate []byte
	Signature   []byte
}

// PageSigner makes the signature in the format the page asked for.
type PageSigner interface {
	Sign(ctx context.Context, request PageSignature) (Signed, error)
}

// CertificateReader returns the certificate of a key (selectcert) and the
// other certificates its store holds, which the ssl: and qualified: filters
// pair it with.
type CertificateReader interface {
	Certificate(key signing.Signer) ([]byte, error)
	Neighbours(key signing.Signer) ([][]byte, error)
}

// DataFetcher downloads data a page pointed at, once the person has seen
// the address and approved.
type DataFetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// FileWriter writes what save and signandsave produce where the person chose.
type FileWriter interface {
	Write(path string, content []byte) error
}

// Courier carries the answer back to the page: the site's storage servlet,
// ciphered with the page's key; it also keeps the page waiting ("#WAIT")
// while the person decides, when the page asked for it.
type Courier interface {
	Deliver(ctx context.Context, channel domain.Channel, answer domain.Answer) error
	// Wait sends "#WAIT" until stop is called.
	Wait(channel domain.Channel) (stop func())
}

// RequestStore fetches a request the page uploaded to the intermediate server
// because it was too long for a URI (C.1–C.3).
type RequestStore interface {
	Fetch(ctx context.Context, retrieveURL, fileID, key, cipher string, asJSON bool) (domain.Invocation, error)
}

// BatchServices are the site's pre- and post-signers (E.3), and its
// single-signature triphase service (E.8), which takes a form body.
type BatchServices interface {
	Presign(ctx context.Context, url string, isJSON bool, batch []byte, chain [][]byte) ([]byte, error)
	Postsign(ctx context.Context, url string, isJSON bool, batch []byte, chain [][]byte, triphase []byte) ([]byte, error)
	Triphase(ctx context.Context, url, body string) ([]byte, error)
}

// ServiceFailure is an HTTP status a batch service answered with, which
// decides the AutoFirma code (E.7).
type ServiceFailure struct {
	Status int
	Body   string
}

// Error describes the failure.
func (f ServiceFailure) Error() string { return fmt.Sprintf("HTTP %d: %s", f.Status, f.Body) }

// RawSigner signs what a site's server prepared (E.4): the digest of each
// input, as PKCS#1 v1.5 for RSA or ECDSA, with one opening of the key.
type RawSigner interface {
	Chain(key signing.Signer) ([][]byte, error)
	SignAll(key signing.Signer, inputs [][]byte, digest string) ([][]byte, error)
}
