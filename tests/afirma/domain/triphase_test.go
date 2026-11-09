package domain_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
)

func TestATriphaseCallIsWrittenAsAutoFirmasServersReadIt(t *testing.T) {
	call := domain.TriphaseCall{Step: "pre", Crypto: domain.Countersign, Format: domain.Format{Family: "xades", Triphase: true},
		Algorithm: "SHA256withRSA", Chain: [][]byte{[]byte("leaf"), []byte("ca")}, Document: []byte("doc-1"),
		Properties: map[string]string{"serverUrl": "https://sede/tri", "documentId": "x", "includeOnlySignningCertificate": "true", "target": "tree"}}
	body := call.Body()
	params := map[string]string{}
	for _, field := range strings.Split(body, "&") {
		key, value, _ := strings.Cut(field, "=")
		params[key] = value
	}
	encoded, _ := base64.URLEncoding.DecodeString(params["params"])
	properties := domain.ParseProperties(string(encoded))
	if params["op"] != "pre" || params["cop"] != "countersign" || params["format"] != "XAdES" ||
		params["cert"] != base64.URLEncoding.EncodeToString([]byte("leaf")) || params["doc"] != base64.URLEncoding.EncodeToString([]byte("doc-1")) ||
		properties["target"] != "tree" || properties["serverUrl"] != "" || properties["documentId"] != "" || params["session"] != "" {
		t.Errorf("%s → %v", body, properties)
	}
	call.Step, call.Session = "post", []byte("<xml/>")
	if !strings.HasSuffix(call.Body(), "&session="+base64.URLEncoding.EncodeToString([]byte("<xml/>"))) {
		t.Error("post carries the session last")
	}
}

func TestTheTriphaseServiceAnswersAreRead(t *testing.T) {
	var failure domain.Failure
	if _, err := domain.ReadTriphasePre([]byte("ERR-21: confirm")); !errors.As(err, &failure) || failure.Code != domain.ContactBatchService {
		t.Errorf("an ERR answer: %v", err)
	}
	empty := base64.URLEncoding.EncodeToString([]byte(`<xml><firmas format="CAdES"></firmas></xml>`))
	if _, err := domain.ReadTriphasePre([]byte(empty)); err == nil {
		t.Error("nothing prepared")
	}
	if id, err := domain.ReadTriphasePost([]byte("OK NEWID=" + base64.URLEncoding.EncodeToString([]byte("sig-9")))); err != nil || string(id) != "sig-9" {
		t.Errorf("%q %v", id, err)
	}
	if _, err := domain.ReadTriphasePost([]byte("ERR-14: failed")); err == nil {
		t.Error("anything but OK NEWID")
	}
}

func TestPropertiesAreEscapedForJava(t *testing.T) {
	text := domain.EncodeProperties(map[string]string{"a key=": "line\none \\ two"})
	if back := domain.ParseProperties(text); back["a key="] != "line\none \\ two" {
		t.Errorf("%q → %v", text, back)
	}
}

// TestABarePresignatureIsTheDocument: NONEtri's server prepares nothing,
// so every pre-signature must be the document, and there must be one.
func TestABarePresignatureIsTheDocument(t *testing.T) {
	document := []byte("expediente-90")
	of := func(pre []byte) domain.TriSign {
		return domain.TriSign{Params: map[string]string{"PRE": base64.StdEncoding.EncodeToString(pre)}}
	}
	if !(domain.TriphaseData{Signs: []domain.TriSign{of(document)}}).PresignsAre(document) {
		t.Error("the document itself")
	}
	for name, data := range map[string]domain.TriphaseData{
		"none":        {},
		"other bytes": {Signs: []domain.TriSign{of(document), of([]byte("otro"))}},
		"unreadable":  {Signs: []domain.TriSign{{Params: map[string]string{"PRE": "%%%"}}}},
	} {
		if data.PresignsAre(document) {
			t.Errorf("%s: accepted", name)
		}
	}
}
