package infrastructure_test

// Single signatures through the site's server (E.8, the "…tri" formats):
// pre prepares what is signed, the key signs it here, post assembles the
// signature on the server, and the page receives the certificate and the
// signature's id.

import (
	"context"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/tests/support/afirmaserver"
)

func triphaseRequest(t *testing.T, id, key, properties, document string) domain.Invocation {
	t.Helper()
	uri := "afirma://sign?jvc=3&ver=3&op=sign&id=" + id + "&key=" + key + "&stservlet=" + url.QueryEscape(storage) +
		"&format=CAdEStri&algorithm=SHA256withECDSA&appname=SedeTest" +
		"&properties=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(properties))) +
		"&dat=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(document)))
	invocation, err := domain.ParseInvocation(uri)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func TestATriphaseSignatureIsMadeThroughTheSitesServer(t *testing.T) {
	server := afirmaserver.New(t)
	outcome := server.EnableTriphase()
	maria, certificate := identity(t, "MARIA GARCIA", 51)
	id, key := sessionID(), "24681357"
	invocation := triphaseRequest(t, id, key, "serverUrl=http://sede.example/TriPhaseSignerServer\nmode=implicit", "expediente-77")
	approver := &recordingApprover{approving: approving{key: maria}}
	if _, err := batchUseCase(server, approver).Execute(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	// The person is told, before approving, which server prepares what is
	// signed.
	if !slices.ContainsFunc(approver.proposal.Warnings, func(warning string) bool {
		return strings.Contains(warning, "prepared by the site's server sede.example")
	}) {
		t.Errorf("the approval does not name the server: %v", approver.proposal.Warnings)
	}

	if len(outcome.Calls) != 2 || !outcome.Verified {
		t.Fatalf("pre then post, the client's signature verifying: %d calls, verified %v", len(outcome.Calls), outcome.Verified)
	}
	pre := outcome.Calls[0]
	document, _ := base64.URLEncoding.DecodeString(pre["doc"])
	params, _ := base64.URLEncoding.DecodeString(pre["params"])
	if pre["op"] != "pre" || pre["cop"] != "sign" || pre["format"] != "CAdES" || pre["algo"] != "SHA256withECDSA" ||
		string(document) != "expediente-77" || !strings.Contains(string(params), "mode=implicit") || strings.Contains(string(params), "serverUrl") {
		t.Errorf("the pre call: %v, params %q", pre, params)
	}
	if outcome.Calls[1]["op"] != "post" || outcome.Calls[1]["session"] == "" {
		t.Errorf("the post call: %v", outcome.Calls[1])
	}

	elements := pageReads(t, server, id, key)
	if len(elements) != 2 || string(elements[0]) != string(certificate.Raw) || string(elements[1]) != "signed-expediente-77" {
		t.Fatalf("the page reads cert|id, got %q", elements)
	}
}

func TestATriphaseSignatureTheServerRefusesIsTheSitesError(t *testing.T) {
	server := afirmaserver.New(t)
	server.EnableTriphase()
	maria, _ := identity(t, "MARIA GARCIA", 52)
	for properties, want := range map[string]string{
		"serverUrl=http://sede.example/TriPhaseSignerServer": "SAF_26",
		"mode=implicit": "SAF_03",
	} {
		id, key := sessionID(), "13572468"
		document := "refuse"
		batchUseCase(server, approving{key: maria}).Execute(context.Background(), triphaseRequest(t, id, key, properties, document))
		history := server.History(id)
		if len(history) == 0 || !strings.HasPrefix(history[len(history)-1], want) {
			t.Errorf("%q: the page reads %v, want %s", properties, history, want)
		}
	}
}

// recordingApprover approves as approving does and keeps the proposal.
type recordingApprover struct {
	approving
	proposal application.Proposal
}

func (r *recordingApprover) Approve(ctx context.Context, proposal application.Proposal) (application.Decision, error) {
	r.proposal = proposal
	return r.approving.Approve(ctx, proposal)
}

// TestAnASiCSContainerIsSignedThroughTheSitesServer: CAdES-ASiC-S-tri and
// XAdES-ASiC-S-tri reach the service as CAdES-ASiC-S and XAdES-ASiC-S, as
// AutoFirma's ASiC triphase signers send them; they are never co-signed.
func TestAnASiCSContainerIsSignedThroughTheSitesServer(t *testing.T) {
	maria, certificate := identity(t, "MARIA GARCIA", 53)
	properties := "serverUrl=http://sede.example/TriPhaseSignerServer"
	for format, service := range map[string]string{"CAdES-ASiC-S-tri": "CAdES-ASiC-S", "XAdES-ASiC-S-tri": "XAdES-ASiC-S"} {
		server := afirmaserver.New(t)
		outcome := server.EnableTriphase()
		id, key := sessionID(), "24681357"
		if _, err := batchUseCase(server, approving{key: maria}).Execute(context.Background(),
			bareRequest(t, id, key, "sign", format, "SHA256withECDSA", properties, []byte("expediente-asics"))); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if len(outcome.Calls) != 2 || !outcome.Verified || outcome.Calls[0]["format"] != service || outcome.Calls[1]["format"] != service {
			t.Errorf("%s: %d calls, verified %v, format %q", format, len(outcome.Calls), outcome.Verified, outcome.Calls[0]["format"])
		}
		if elements := pageReads(t, server, id, key); len(elements) != 2 || string(elements[0]) != string(certificate.Raw) {
			t.Errorf("%s: the page reads cert|id, got %q", format, elements)
		}

		cosigned := sessionID()
		batchUseCase(server, approving{key: maria}).Execute(context.Background(),
			bareRequest(t, cosigned, key, "cosign", format, "SHA256withECDSA", properties, []byte("PK\x03\x04")))
		if history := server.History(cosigned); len(history) == 0 || !strings.HasPrefix(history[len(history)-1], "SAF_04") || len(outcome.Calls) != 2 {
			t.Errorf("%s: a co-signature reached the server or was not refused: %v", format, history)
		}
	}
}
