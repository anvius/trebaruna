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
	Items    []domain.BatchItem
	Filter   domain.CertificateFilter
	Warnings []string
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

// CertificateReader returns the certificate of a key (selectcert).
type CertificateReader interface {
	Certificate(key signing.Signer) ([]byte, error)
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

// BatchServices are the site's pre- and post-signers (E.3).
type BatchServices interface {
	Presign(ctx context.Context, url string, isJSON bool, batch []byte, chain [][]byte) ([]byte, error)
	Postsign(ctx context.Context, url string, isJSON bool, batch []byte, chain [][]byte, triphase []byte) ([]byte, error)
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
