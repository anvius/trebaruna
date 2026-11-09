package application_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

type scriptedApprover struct {
	decision  application.Decision
	proposals []application.Proposal
}

func (s *scriptedApprover) Approve(_ context.Context, proposal application.Proposal) (application.Decision, error) {
	s.proposals = append(s.proposals, proposal)
	return s.decision, nil
}

type recordingSigner struct{ requests []application.PageSignature }

func (r *recordingSigner) Sign(_ context.Context, request application.PageSignature) (application.Signed, error) {
	r.requests = append(r.requests, request)
	return application.Signed{Certificate: holder, Signature: append([]byte("signed:"), request.Data...)}, nil
}

// holder is the certificate every scripted key has: valid now, CN MARIA.
var holder = func() []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "MARIA GARCIA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	raw, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	return raw
}()

type fixedCertificate struct{}

func (fixedCertificate) Certificate(signing.Signer) ([]byte, error) { return holder, nil }

type recordingFetcher struct{ fetched []string }

func (r *recordingFetcher) Fetch(_ context.Context, url string) ([]byte, error) {
	r.fetched = append(r.fetched, url)
	return []byte("downloaded"), nil
}

type memoryFiles map[string][]byte

func (m memoryFiles) Write(path string, content []byte) error { m[path] = content; return nil }

type recordingCourier struct {
	mutex     sync.Mutex
	delivered []domain.Answer
	waits     int
	stopped   int
}

func (r *recordingCourier) Deliver(_ context.Context, _ domain.Channel, answer domain.Answer) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.delivered = append(r.delivered, answer)
	return nil
}

func (r *recordingCourier) Wait(domain.Channel) func() {
	r.waits++
	return func() { r.stopped++ }
}

type fixture struct {
	approver *scriptedApprover
	signer   *recordingSigner
	fetcher  *recordingFetcher
	files    memoryFiles
	courier  *recordingCourier
	use      *application.AnswerPage
}

func newFixture(t *testing.T, approved bool) fixture {
	t.Helper()
	key, err := signing.NewSigner("MARIA", signing.FromP12, signing.WithKeyMaterial([]byte("p12")))
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{
		approver: &scriptedApprover{decision: application.Decision{Approved: approved, Key: key, SavePath: "/tmp/out"}},
		signer:   &recordingSigner{}, fetcher: &recordingFetcher{}, files: memoryFiles{}, courier: &recordingCourier{},
	}
	f.use = application.NewAnswerPage(f.approver, f.signer, fixedCertificate{}, f.fetcher, f.files, f.courier, nil)
	return f
}

func invocation(t *testing.T, uri string) domain.Invocation {
	t.Helper()
	parsed, err := domain.ParseInvocation(uri)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

const intermediate = "&id=Ab1234567890123456cd&stservlet=https%3A%2F%2Fsede.example%2FStorageService&aw=true&appname=SEDE"

// TestNothingIsSignedBeforeAPersonApproves (ADR-0004).
func TestNothingIsSignedBeforeAPersonApproves(t *testing.T) {
	f := newFixture(t, false)
	answer, err := f.use.Execute(context.Background(), invocation(t, "afirma://sign?format=CAdES&algorithm=SHA256&dat=aG9sYQ%3D%3D"+intermediate))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.signer.requests) != 0 || answer.Text() != "CANCEL" || len(f.courier.delivered) != 1 || f.courier.delivered[0].Text() != "CANCEL" {
		t.Errorf("signed %d times, answered %q", len(f.signer.requests), answer.Text())
	}
}

// TestAnApprovedSignatureIsDeliveredToTheSite.
func TestAnApprovedSignatureIsDeliveredToTheSite(t *testing.T) {
	f := newFixture(t, true)
	answer, err := f.use.Execute(context.Background(), invocation(t, "afirma://sign?format=CAdES&algorithm=SHA256withRSA&key=12345678&dat=aG9sYQ%3D%3D"+intermediate))
	if err != nil {
		t.Fatal(err)
	}
	proposal := f.approver.proposals[0]
	if proposal.Site != "sede.example" || proposal.AppName != "SEDE" || proposal.DataSize != 4 || proposal.Format != "CAdES" {
		t.Errorf("proposal %+v", proposal)
	}
	if len(proposal.Warnings) == 0 || !strings.Contains(proposal.Warnings[0], "single DES") {
		t.Errorf("the DES weakness must be said: %v", proposal.Warnings)
	}
	if string(f.signer.requests[0].Data) != "hola" || f.signer.requests[0].Crypto != domain.Sign {
		t.Errorf("signed %+v", f.signer.requests[0])
	}
	if answer.Text() != domain.SignAnswer(holder, []byte("signed:hola"), "", 0).Text() || len(f.courier.delivered) != 1 {
		t.Errorf("answer %q", answer.Text())
	}
	if f.courier.waits != 1 || f.courier.stopped != 1 {
		t.Errorf("the page must be kept waiting while the person decides, then released: %d/%d", f.courier.waits, f.courier.stopped)
	}
}

// TestADataAddressIsShownThenFetched: AutoFirma downloads it silently.
func TestADataAddressIsShownThenFetched(t *testing.T) {
	f := newFixture(t, true)
	if _, err := f.use.Execute(context.Background(), invocation(t, "afirma://sign?format=CAdES&algorithm=SHA256&dat=https%3A%2F%2Fsede.example%2Fdoc.pdf")); err != nil {
		t.Fatal(err)
	}
	if f.approver.proposals[0].DataURL != "https://sede.example/doc.pdf" || len(f.fetcher.fetched) != 1 || string(f.signer.requests[0].Data) != "downloaded" {
		t.Errorf("proposal %+v, fetched %v", f.approver.proposals[0], f.fetcher.fetched)
	}

	refused := newFixture(t, false)
	refused.use.Execute(context.Background(), invocation(t, "afirma://sign?format=CAdES&algorithm=SHA256&dat=https%3A%2F%2Fsede.example%2Fdoc.pdf"))
	if len(refused.fetcher.fetched) != 0 {
		t.Error("nothing is downloaded before approval")
	}
}

// TestAnInvalidRequestReachesThePageAsAFailure.
func TestAnInvalidRequestReachesThePageAsAFailure(t *testing.T) {
	f := newFixture(t, true)
	answer, err := f.use.Execute(context.Background(), invocation(t, "afirma://sign?format=OOXML&algorithm=SHA256"+intermediate))
	var failure domain.Failure
	if !errors.As(err, &failure) || failure.Code != domain.UnsupportedFormat {
		t.Fatalf("got %v", err)
	}
	if answer.Text() != "SAF_06: Formato de firma no soportado" || len(f.courier.delivered) != 1 || len(f.approver.proposals) != 0 {
		t.Errorf("answer %q, delivered %d, asked %d", answer.Text(), len(f.courier.delivered), len(f.approver.proposals))
	}
}

// TestCounterSignaturesAndSignAndSave.
func TestCounterSignaturesAndSignAndSave(t *testing.T) {
	f := newFixture(t, true)
	f.use.Execute(context.Background(), invocation(t, "afirma://signandsave?cop=countersign&format=CAdES&algorithm=SHA256&filename=firma.p7m&dat=aG9sYQ%3D%3D"))
	if f.signer.requests[0].Crypto != domain.Countersign || string(f.files["/tmp/out"]) != "signed:hola" ||
		f.approver.proposals[0].SuggestedName != "firma.p7m" {
		t.Errorf("signandsave %+v, saved %q", f.signer.requests[0], f.files["/tmp/out"])
	}
}

// TestSelectCertAndSaveAndTheBlockedChannels.
func TestSelectCertAndSaveAndTheBlockedChannels(t *testing.T) {
	f := newFixture(t, true)
	answer, _ := f.use.Execute(context.Background(), invocation(t, "afirma://selectcert?properties="+
		base64.StdEncoding.EncodeToString([]byte("filter=subject.contains:maria"))))
	if answer.Text() != domain.EncodeBase64URL(holder) || len(f.approver.proposals[0].Filter.Expressions()) != 1 {
		t.Errorf("selectcert %q, filter %v", answer.Text(), f.approver.proposals[0].Filter.Expressions())
	}
	saved, _ := f.use.Execute(context.Background(), invocation(t, "afirma://save?dat=aG9sYQ%3D%3D&filename=nota.txt"))
	if saved.Text() != "OK" || string(f.files["/tmp/out"]) != "hola" {
		t.Errorf("save %q", saved.Text())
	}
	if _, err := f.use.Execute(context.Background(), invocation(t, "afirma://websocket?ports=63117&v=4")); err == nil {
		t.Error("the WebSocket channel is not offered")
	}
	if loaded, _ := f.use.Execute(context.Background(), invocation(t, "afirma://load?exts=pdf")); !strings.HasPrefix(loaded.Text(), "SAF_04") {
		t.Errorf("load %q", loaded.Text())
	}
}

// TestACertificateThePageDoesNotAcceptIsRefusedAndAskedAgain: AutoFirma only
// offers matching certificates; trebaruna refuses the choice with the reason.
func TestACertificateThePageDoesNotAcceptIsRefusedAndAskedAgain(t *testing.T) {
	f := newFixture(t, true)
	properties := base64.StdEncoding.EncodeToString([]byte("filter=subject.contains:ROSSI"))
	answer, err := f.use.Execute(context.Background(), invocation(t, "afirma://sign?format=CAdES&algorithm=SHA256&dat=aG9sYQ%3D%3D&properties="+properties))
	if len(f.approver.proposals) != 3 || f.approver.proposals[0].Rejected != "" || !strings.Contains(f.approver.proposals[1].Rejected, "MARIA GARCIA") {
		t.Errorf("proposals %d, rejected %q", len(f.approver.proposals), f.approver.proposals[len(f.approver.proposals)-1].Rejected)
	}
	if len(f.signer.requests) != 0 || !strings.HasPrefix(answer.Text(), "SAF_19") || err == nil {
		t.Errorf("nothing may be signed with a certificate the page refuses: %q", answer.Text())
	}
}
