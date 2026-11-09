package infrastructure_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"
)

// TestThePageRequestIsDrivenThroughTheCommandsPipes: the proposal is read,
// the decision with its secret goes to stdin, the outcome comes back.
func TestThePageRequestIsDrivenThroughTheCommandsPipes(t *testing.T) {
	received := filepath.Join(t.TempDir(), "decision")
	proposal := `{"type":"proposal","operation":"sign","site":"sede.example","app_name":"SEDE","format":"CAdES","data_size":4,"items":[],"filters":["dnie:"],"warnings":["single DES"]}`
	outcome := `{"type":"outcome","answer":"Y2VydA==|c2ln","delivered":true}`
	binary, recorded := fakeCommand(t, "echo '"+proposal+"'; read line; printf '%s' \"$line\" > "+received+"; echo '"+outcome+"'")

	session, err := infrastructure.CommandLinePageRequests{BinaryPath: binary}.Open(context.Background(), "afirma://sign?x=1")
	if err != nil {
		t.Fatal(err)
	}
	step, err := session.Next()
	if err != nil || step.Proposal == nil || step.Proposal.Site != "sede.example" || step.Proposal.Filters[0] != "dnie:" {
		t.Fatalf("proposal %+v, %v", step.Proposal, err)
	}
	if err := session.Decide(domain.PageDecision{Approved: true, Card: domain.CardKey{Token: "DNI", Fingerprint: "a18a", PIN: "123456"}}); err != nil {
		t.Fatal(err)
	}
	step, err = session.Next()
	if err != nil || step.Outcome == nil || !step.Outcome.Succeeded() {
		t.Fatalf("outcome %+v, %v", step.Outcome, err)
	}
	session.Close()

	arguments := recordedArguments(t, recorded)
	if strings.Join(arguments, " ") != "afirma afirma://sign?x=1 --interactive" {
		t.Errorf("arguments %v", arguments)
	}
	decision, _ := os.ReadFile(received)
	for _, wanted := range []string{`"card":true`, `"token":"DNI"`, `"certificate":"a18a"`, `"pin":"123456"`} {
		if !strings.Contains(string(decision), wanted) {
			t.Errorf("decision %s lacks %s", decision, wanted)
		}
	}
}

// TestAnIncompleteApprovalNeverReachesTheCommand.
func TestAnIncompleteApprovalNeverReachesTheCommand(t *testing.T) {
	proposal := domain.PageProposal{Operation: "signandsave", ChooseFile: true}
	cases := []struct {
		decision domain.PageDecision
		want     domain.ProblemCode
	}{
		{domain.PageDecision{Approved: true}, domain.ProblemMissingKey},
		{domain.PageDecision{Approved: true, KeyFile: domain.CertificateFile{Path: "/k.p12"}}, domain.ProblemMissingDocument},
		{domain.PageDecision{Approved: true, KeyFile: domain.CertificateFile{Path: "/k.p12"}, Document: "/d.pdf"}, domain.ProblemMissingSaveTo},
	}
	for _, entry := range cases {
		err := entry.decision.Validate(proposal)
		if problem, ok := err.(domain.Problem); !ok || problem.Code != entry.want {
			t.Errorf("%+v: %v, want %s", entry.decision, err, entry.want)
		}
	}
	if err := (domain.PageDecision{}).Validate(proposal); err != nil {
		t.Errorf("declining needs nothing: %v", err)
	}
}

// TestAKeptCertificateTravelsWithoutTheKey: the window approves with the
// certificate the page asked to keep, and no key or secret goes back.
func TestAKeptCertificateTravelsWithoutTheKey(t *testing.T) {
	received := filepath.Join(t.TempDir(), "decision")
	proposal := `{"type":"proposal","operation":"sign","site":"sede.example","format":"CAdES","data_size":4,"items":[],"remembered":"MARIA GARCIA"}`
	outcome := `{"type":"outcome","answer":"Y2VydA==|c2ln","delivered":true,"session":true}`
	binary, _ := fakeCommand(t, "echo '"+proposal+"'; read line; printf '%s' \"$line\" > "+received+"; echo '"+outcome+"'")
	session, err := infrastructure.CommandLinePageRequests{BinaryPath: binary}.Open(context.Background(), "afirma://websocket?v=4")
	if err != nil {
		t.Fatal(err)
	}
	step, err := session.Next()
	if err != nil || step.Proposal == nil || step.Proposal.Remembered != "MARIA GARCIA" {
		t.Fatalf("proposal %+v, %v", step.Proposal, err)
	}
	if err := session.Decide(domain.PageDecision{Approved: true, Remembered: true}); err != nil {
		t.Fatal(err)
	}
	session.Next()
	session.Close()
	decision, _ := os.ReadFile(received)
	if !strings.Contains(string(decision), `"remembered":true`) || strings.Contains(string(decision), `"key"`) || strings.Contains(string(decision), `"pin"`) {
		t.Errorf("decision %s", decision)
	}
}

// TestThePlacedSealTravelsInPoints: the page asks for a seal on a copy of
// its PDF, and the box goes back in PDF points.
func TestThePlacedSealTravelsInPoints(t *testing.T) {
	received := filepath.Join(t.TempDir(), "decision")
	proposal := `{"type":"proposal","operation":"sign","site":"sede.example","format":"PAdES","data_size":4,"items":[],"seal":"want","seal_document":"/tmp/x/document.pdf"}`
	outcome := `{"type":"outcome","answer":"Y2VydA==|c2ln","delivered":true}`
	binary, _ := fakeCommand(t, "echo '"+proposal+"'; read line; printf '%s' \"$line\" > "+received+"; echo '"+outcome+"'")
	session, err := infrastructure.CommandLinePageRequests{BinaryPath: binary}.Open(context.Background(), "afirma://sign?x=1")
	if err != nil {
		t.Fatal(err)
	}
	step, err := session.Next()
	if err != nil || step.Proposal == nil || step.Proposal.Seal != "want" || step.Proposal.SealDocument != "/tmp/x/document.pdf" {
		t.Fatalf("proposal %+v, %v", step.Proposal, err)
	}
	seal := domain.SealChoice{Page: 2, Rect: domain.SealRect{LowerLeftX: 300, LowerLeftY: 60.5, UpperRightX: 520, UpperRightY: 120}}
	if err := session.Decide(domain.PageDecision{Approved: true, KeyFile: domain.CertificateFile{Path: "/k.p12"}, Seal: seal}); err != nil {
		t.Fatal(err)
	}
	session.Next()
	session.Close()
	decision, _ := os.ReadFile(received)
	if !strings.Contains(string(decision), `"seal":{"llx":300,"lly":60.5,"page":2,"urx":520,"ury":120}`) {
		t.Errorf("decision %s", decision)
	}
}
