package infrastructure_test

// Single signatures through the site's server (E.8, the "…tri" formats):
// pre prepares what is signed, the key signs it here, post assembles the
// signature on the server, and the page receives the certificate and the
// signature's id.

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

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
	if _, err := batchUseCase(server, approving{key: maria}).Execute(context.Background(), invocation); err != nil {
		t.Fatal(err)
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
