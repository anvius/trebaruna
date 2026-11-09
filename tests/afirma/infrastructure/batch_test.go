package infrastructure_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	"codeberg.org/simplicer/trebaruna/tests/support/afirmaserver"
)

func batchUseCase(server *afirmaserver.Server, approver application.Approver) *application.AnswerPage {
	services := infrastructure.BatchServices{Client: server.Client()}
	return useCase(server, approver).WithBatches(services, infrastructure.KeyRawSigner{})
}

// TestAJSONBatchIsSignedThroughTheSitesServers is Sistema RED's request
// shape (G.2): intermediate server, JSON batch, needcert, a subject filter.
// The post-signer verifies every PK1 against its PRE with the certificate it
// received; a document the pre-signer could not prepare is reported, not
// signed.
func TestAJSONBatchIsSignedThroughTheSitesServers(t *testing.T) {
	server := afirmaserver.New(t)
	outcome := server.EnableBatches()
	maria, certificate := identity(t, "MARIA GARCIA", 41)
	id, key := sessionID(), "13572468"
	batch := `{"stoponerror":false,"algorithm":"SHA256withRSA","format":"CAdES","suboperation":"sign","singlesigns":[` +
		`{"id":"doc1","datareference":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `","extraparams":"bW9kZT1leHBsaWNpdA=="},` +
		`{"id":"keep2","datareference":"ref2"},{"id":"gone3","datareference":"unprepared"}]}`
	properties := base64.StdEncoding.EncodeToString([]byte("filters.1=subject.rfc2254:(cn=MARIA*)\nfilters.2=subject.rfc2254:(cn=*GARCIA)"))
	uri := "afirma://batch?jvc=3&ver=3&op=batch&id=" + id + "&key=" + key + "&keystore=MOZ_UNI" +
		"&stservlet=" + url.QueryEscape(storage) +
		"&batchpresignerurl=" + url.QueryEscape("http://sede.example/JSONBatchPresigner") +
		"&batchpostsignerurl=" + url.QueryEscape("http://sede.example/JSONBatchPostsigner") +
		"&aw=true&appname=SistemaRED&properties=" + url.QueryEscape(properties) +
		"&needcert=true&jsonbatch=true&dat=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(batch)))
	invocation, err := domain.ParseInvocation(uri)
	if err != nil {
		t.Fatal(err)
	}

	recorder := &proposalRecorder{approving: approving{key: maria, delay: 40 * time.Millisecond}}
	if _, err := batchUseCase(server, recorder).Execute(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	proposal := recorder.proposal
	if len(proposal.Items) != 3 || proposal.Site != "sede.example" || len(proposal.Filter.Expressions()) != 2 {
		t.Errorf("the person must see the batch's documents, site and filters: %+v", proposal)
	}

	if !slices.Equal(outcome.Verified, []string{"doc1", "keep2"}) || len(outcome.Failed) != 0 {
		t.Fatalf("verified %v, failed %v", outcome.Verified, outcome.Failed)
	}
	if outcome.PREKept["doc1"] || !outcome.PREKept["keep2"] {
		t.Errorf("PRE is removed unless NEED_PRE: %v", outcome.PREKept)
	}
	if !strings.Contains(string(outcome.PostedBatch), `"result":"ERROR_PRE"`) || strings.Contains(string(outcome.PostedBatch), "unprepared") {
		t.Errorf("the unprepared document must reach post-sign as a result, without its reference: %s", outcome.PostedBatch)
	}

	elements := pageReads(t, server, id, key)
	if len(elements) != 2 || string(elements[1]) != string(certificate.Raw) {
		t.Fatalf("the page reads result|cert, got %d elements", len(elements))
	}
	var result struct {
		Signs []struct {
			ID     string `json:"id"`
			Result string `json:"result"`
		} `json:"signs"`
	}
	if err := json.Unmarshal(elements[0], &result); err != nil || len(result.Signs) != 2 || result.Signs[0].Result != "DONE_AND_SAVED" {
		t.Errorf("result %s, %v", elements[0], err)
	}
}

// TestAnXMLBatchIsSignedToo.
func TestAnXMLBatchIsSignedToo(t *testing.T) {
	server := afirmaserver.New(t)
	outcome := server.EnableBatches()
	maria, _ := identity(t, "MARIA GARCIA", 42)
	batch := `<signbatch stoponerror="false" algorithm="SHA256withECDSA"><singlesign Id="a"><datasource>x</datasource>` +
		`<format>CAdES</format><suboperation>sign</suboperation></singlesign><singlesign Id="b"><datasource>y</datasource>` +
		`<format>CAdES</format><suboperation>sign</suboperation></singlesign></signbatch>`
	uri := "afirma://batch?batchpresignerurl=" + url.QueryEscape("http://sede.example/XMLBatchPresigner") +
		"&batchpostsignerurl=" + url.QueryEscape("http://sede.example/XMLBatchPostsigner") +
		"&dat=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(batch)))
	invocation, _ := domain.ParseInvocation(uri)
	answer, err := batchUseCase(server, approving{key: maria}).Execute(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(outcome.Verified, []string{"a", "b"}) {
		t.Fatalf("verified %v", outcome.Verified)
	}
	result, _ := base64.StdEncoding.DecodeString(strings.Split(answer.Text(), "|")[0])
	if !strings.Contains(string(result), `result="DONE_AND_SAVED"`) || strings.Contains(answer.Text(), "|") {
		t.Errorf("answer %q: result only, no certificate without needcert", result)
	}
}

// TestALocalBatchSignsEachDocumentHere (E.6).
func TestALocalBatchSignsEachDocumentHere(t *testing.T) {
	server := afirmaserver.New(t)
	maria, _ := identity(t, "MARIA GARCIA", 43)
	batch := `{"algorithm":"SHA256","format":"CAdES","stoponerror":true,"singlesigns":[` +
		`{"id":"uno","datareference":"aG9sYQ=="},{"id":"due","datareference":"!!!"},{"id":"tre","datareference":"aG9sYQ=="}]}`
	uri := "afirma://batch?localBatchProcess=true&jsonbatch=true&dat=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(batch)))
	invocation, _ := domain.ParseInvocation(uri)
	answer, err := batchUseCase(server, approving{key: maria}).Execute(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := base64.StdEncoding.DecodeString(answer.Text())
	var parsed struct {
		Signs []struct {
			ID, Result, Signature string
		} `json:"signs"`
	}
	json.Unmarshal(result, &parsed)
	got := []string{}
	for _, sign := range parsed.Signs {
		got = append(got, sign.ID+":"+sign.Result)
	}
	if !slices.Equal(got, []string{"uno:DONE_AND_SAVED", "due:ERROR_PRE", "tre:SKIPPED"}) || parsed.Signs[0].Signature == "" {
		t.Errorf("results %v", got)
	}
}

// TestABatchServiceErrorBecomesTheRightCode (E.7).
func TestABatchServiceErrorBecomesTheRightCode(t *testing.T) {
	server := afirmaserver.New(t)
	maria, _ := identity(t, "MARIA GARCIA", 44)
	uri := "afirma://batch?batchpresignerurl=" + url.QueryEscape("http://sede.example/Missing") +
		"&batchpostsignerurl=" + url.QueryEscape("http://sede.example/Missing") + "&jsonbatch=true&dat=" +
		url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(`{"algorithm":"SHA256","singlesigns":[{"id":"a"}]}`)))
	invocation, _ := domain.ParseInvocation(uri)
	answer, _ := batchUseCase(server, approving{key: maria}).Execute(context.Background(), invocation)
	if !strings.HasPrefix(answer.Text(), "SAF_26") {
		t.Errorf("a 404 from the batch service is SAF_26: %q", answer.Text())
	}
}

type proposalRecorder struct {
	approving
	proposal application.Proposal
}

func (r *proposalRecorder) Approve(ctx context.Context, proposal application.Proposal) (application.Decision, error) {
	r.proposal = proposal
	return r.approving.Approve(ctx, proposal)
}
