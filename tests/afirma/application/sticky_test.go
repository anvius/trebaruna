package application_test

// sticky and resetsticky: the key chosen for one request of a page is
// offered again at its next request in the same process (a WebSocket
// session), never used without the person approving, and still held to
// the page's filters.

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// sequenceApprover answers each proposal with the next decision.
type sequenceApprover struct {
	decisions []application.Decision
	proposals []application.Proposal
}

func (s *sequenceApprover) Approve(_ context.Context, proposal application.Proposal) (application.Decision, error) {
	s.proposals = append(s.proposals, proposal)
	decision := s.decisions[0]
	s.decisions = s.decisions[1:]
	return decision, nil
}

func stickySign(t *testing.T, extra string) domain.Invocation {
	t.Helper()
	return invocation(t, "afirma://sign?format=CAdES&algorithm=SHA256&dat=aG9sYQ%3D%3D"+extra)
}

func TestAKeptKeyIsOfferedAtThePagesNextRequest(t *testing.T) {
	key, _ := signing.NewSigner("MARIA", signing.FromP12, signing.WithKeyMaterial([]byte("p12")))
	approver := &sequenceApprover{decisions: []application.Decision{
		{Approved: true, Key: key}, {Approved: true, UseRemembered: true}, {Approved: true, Key: key},
		{Approved: true, Key: key}, {Approved: true, Key: key},
	}}
	signer := &recordingSigner{}
	use := application.NewAnswerPage(approver, signer, fixedCertificate{}, &recordingFetcher{}, memoryFiles{}, &recordingCourier{}, nil)

	requests := []string{"&sticky=true", "&sticky=true", "&resetsticky=true", "&sticky=true", "&sticky=false"}
	for _, extra := range requests {
		if _, err := use.Execute(context.Background(), stickySign(t, extra)); err != nil {
			t.Fatalf("%s: %v", extra, err)
		}
	}
	if len(signer.requests) != len(requests) || signer.requests[1].Key.Name() != "MARIA" {
		t.Fatalf("approving with the kept key signs with it: %d signatures", len(signer.requests))
	}
	for index, want := range []string{"", "MARIA GARCIA", "", "", ""} {
		if got := approver.proposals[index].Remembered; got != want {
			t.Errorf("request %d (%s) offers %q, want %q", index+1, requests[index], got, want)
		}
	}
	// 1: nothing kept yet; 2: the key kept at 1; 3: resetsticky forgets it,
	// and keeps nothing; 4: so nothing is offered; 5: what 4 kept is not
	// offered to a request without sticky.
}

func TestNoKeptKeyMeansNoApprovalWithIt(t *testing.T) {
	approver := &sequenceApprover{decisions: []application.Decision{{Approved: true, UseRemembered: true}}}
	signer := &recordingSigner{}
	use := application.NewAnswerPage(approver, signer, fixedCertificate{}, &recordingFetcher{}, memoryFiles{}, &recordingCourier{}, nil)
	answer, _ := use.Execute(context.Background(), stickySign(t, "&sticky=true"))
	if !strings.HasPrefix(answer.Text(), "SAF_08") || len(signer.requests) != 0 {
		t.Errorf("approving with a kept key that does not exist: %q", answer.Text())
	}
}

// TestAKeptKeyIsHeldToTheNextPagesFilters: keeping a key does not let it
// past filters it does not match.
func TestAKeptKeyIsHeldToTheNextPagesFilters(t *testing.T) {
	key, _ := signing.NewSigner("MARIA", signing.FromP12, signing.WithKeyMaterial([]byte("p12")))
	approver := &sequenceApprover{decisions: []application.Decision{
		{Approved: true, Key: key}, {Approved: true, UseRemembered: true}, {}, {},
	}}
	signer := &recordingSigner{}
	use := application.NewAnswerPage(approver, signer, fixedCertificate{}, &recordingFetcher{}, memoryFiles{}, &recordingCourier{}, nil)
	use.Execute(context.Background(), stickySign(t, "&sticky=true"))
	filtered := "&sticky=true&properties=" + base64.StdEncoding.EncodeToString([]byte("filter=subject.contains:ROSSI"))
	answer, _ := use.Execute(context.Background(), stickySign(t, filtered))
	if len(signer.requests) != 1 || !strings.Contains(approver.proposals[2].Rejected, "MARIA GARCIA") || answer.Text() != "CANCEL" {
		t.Errorf("the kept key was not refused by the filter: %d signatures, %q", len(signer.requests), answer.Text())
	}
}
