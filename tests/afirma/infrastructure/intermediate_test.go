package infrastructure_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/tests/support/afirmaserver"
)

// TestDESMatchesTheProtocolsVector (C.5): key 12345678, "hi" → 6.B1abIF3v_Do=.
func TestDESMatchesTheProtocolsVector(t *testing.T) {
	sealed, err := infrastructure.DESEnvelope("12345678", []byte("hi"))
	if err != nil || sealed != "6.B1abIF3v_Do=" {
		t.Fatalf("got %q, %v", sealed, err)
	}
	for _, text := range []string{"6.B1abIF3v_Do=", "6.B1abIF3v/Do="} {
		plain, err := infrastructure.OpenDESEnvelope("12345678", text)
		if err != nil || string(plain) != "hi" {
			t.Errorf("%s: %q, %v", text, plain, err)
		}
	}
	exact, _ := infrastructure.DESEnvelope("12345678", []byte("12345678"))
	if !strings.HasPrefix(exact, "0.") {
		t.Errorf("a whole block needs no padding: %q", exact)
	}
}

// approving is a person who says yes after a moment, long enough for the
// page to hear "#WAIT".
type approving struct {
	key   signing.Signer
	delay time.Duration
}

func (a approving) Approve(context.Context, application.Proposal) (application.Decision, error) {
	time.Sleep(a.delay)
	return application.Decision{Approved: a.key.KeySource() != "", Key: a.key}, nil
}

func useCase(server *afirmaserver.Server, approver application.Approver) *application.AnswerPage {
	courier := infrastructure.WithClient(server.Client())
	courier.Interval = 20 * time.Millisecond
	return application.NewAnswerPage(approver, infrastructure.NewNativePageSigner(), infrastructure.KeyCertificates{},
		infrastructure.WebData{}, infrastructure.LocalFiles{}, courier, courier)
}

func sessionID() string {
	alphabet := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	random := make([]byte, 20)
	rand.Read(random)
	for index := range random {
		random[index] = alphabet[int(random[index])%len(alphabet)]
	}
	return string(random)
}

const storage = "http://sede.example/StorageService"
const retrieve = "http://sede.example/RetrieveService"

// pageReads decrypts what the page finds under its session id.
func pageReads(t *testing.T, server *afirmaserver.Server, id, key string) [][]byte {
	t.Helper()
	history := server.History(id)
	if len(history) == 0 {
		t.Fatal("nothing was stored for the page")
	}
	result := history[len(history)-1]
	var elements [][]byte
	for _, element := range strings.Split(result, "|") {
		plain, err := infrastructure.OpenDESEnvelope(key, element)
		if err != nil {
			t.Fatalf("the page cannot decipher %q: %v", element, err)
		}
		elements = append(elements, plain)
	}
	return elements
}

// TestAShortRequestIsAnsweredThroughTheIntermediateServer: the page keeps
// hearing #WAIT while the person decides, then reads a ciphered cert|sig that
// OpenSSL verifies.
func TestAShortRequestIsAnsweredThroughTheIntermediateServer(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	server := afirmaserver.New(t)
	maria, certificate := identity(t, "MARIA GARCIA", 21)
	id, key := sessionID(), "87654321"
	data := []byte("Solicitud de alta\n")
	uri := "afirma://sign?jvc=3&ver=3&op=sign&id=" + id + "&key=" + key + "&stservlet=" + url.QueryEscape(storage) +
		"&format=CAdES&algorithm=SHA256withRSA&aw=true&appname=SEDE&dat=" + base64.URLEncoding.EncodeToString(data)
	invocation, err := domain.ParseInvocation(uri)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := useCase(server, approving{key: maria, delay: 80 * time.Millisecond}).Execute(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	history := server.History(id)
	if len(history) < 2 || history[0] != "#WAIT" {
		t.Errorf("the page must hear #WAIT before the result: %q", history)
	}
	elements := pageReads(t, server, id, key)
	if len(elements) != 2 || !bytes.Equal(elements[0], certificate.Raw) {
		t.Fatalf("the page read %d elements", len(elements))
	}
	directory := t.TempDir()
	opensslVerify(t, "-in", write(t, directory, "firma.p7m", elements[1]))

	time.Sleep(60 * time.Millisecond)
	if last := server.History(id); last[len(last)-1] != history[len(history)-1] {
		t.Error("no #WAIT may follow the result")
	}
}

// TestAnUploadedRequestIsFetchedThenAnswered: a request too long for a URI is
// uploaded by the page, ciphered, under a fresh file id (C.1).
func TestAnUploadedRequestIsFetchedThenAnswered(t *testing.T) {
	server := afirmaserver.New(t)
	maria, _ := identity(t, "MARIA GARCIA", 22)
	id, fileID, key := sessionID(), sessionID(), "11223344"
	data := bytes.Repeat([]byte("documento largo "), 300)
	// autoscript neither URL-encodes nor escapes the values: a "+" of the
	// standard Base64 reaches the client as a space.
	xml := `<sign><e k="ver" v="3"/><e k="op" v="sign"/><e k="id" v="` + id + `"/><e k="key" v="` + key +
		`"/><e k="stservlet" v="` + storage + `"/><e k="format" v="CAdES"/><e k="algorithm" v="SHA256withRSA"/>` +
		`<e k="properties" v="` + base64.StdEncoding.EncodeToString([]byte("mode=explicit")) + `"/>` +
		`<e k="dat" v="` + base64.StdEncoding.EncodeToString(data) + `"/></sign>`
	sealed, _ := infrastructure.DESEnvelope(key, []byte(xml))
	server.Put(fileID, sealed)

	uri := "afirma://sign?fileid=" + fileID + "&rtservlet=" + url.QueryEscape(retrieve) + "&key=" + key
	invocation, _ := domain.ParseInvocation(uri)
	if _, err := useCase(server, approving{key: maria}).Execute(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	elements := pageReads(t, server, id, key)
	if len(elements) != 2 {
		t.Fatalf("elements %d", len(elements))
	}
	if _, err := exec.LookPath("openssl"); err == nil {
		directory := t.TempDir()
		opensslVerify(t, "-in", write(t, directory, "firma.p7s", elements[1]), "-content", write(t, directory, "data", data), "-binary")
	}
	if _, read := server.Take(fileID); read {
		t.Error("the uploaded request is read once")
	}
}

// TestAutoscript110AESIsUnderstood (C.8): the request uploaded with AES, the
// answer ciphered with AES and the same IV for each element.
func TestAutoscript110AESIsUnderstood(t *testing.T) {
	server := afirmaserver.New(t)
	maria, certificate := identity(t, "MARIA GARCIA", 23)
	id, fileID, key := sessionID(), sessionID(), "55667788"
	aesKey, iv := make([]byte, 32), make([]byte, 16)
	rand.Read(aesKey)
	rand.Read(iv)
	parameters, _ := json.Marshal(map[string]string{"algo": "AES", "key": base64.StdEncoding.EncodeToString(aesKey),
		"iv": base64.StdEncoding.EncodeToString(iv), "legDes": key})
	cipher := base64.URLEncoding.EncodeToString(parameters)
	xml := `<sign><e k="op" v="sign"/><e k="id" v="` + id + `"/><e k="stservlet" v="` + storage +
		`"/><e k="format" v="CAdES"/><e k="algorithm" v="SHA256"/><e k="dat" v="aG9sYQ=="/></sign>`
	sealed, _ := infrastructure.AESEnvelope(aesKey, iv, []byte(xml))
	server.Put(fileID, sealed)

	uri := "afirma://sign?fileid=" + fileID + "&rtservlet=" + url.QueryEscape(retrieve) + "&key=" + key + "&cipher=" + cipher
	invocation, _ := domain.ParseInvocation(uri)
	if _, err := useCase(server, approving{key: maria}).Execute(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	history := server.History(id)
	elements := strings.Split(history[len(history)-1], "|")
	first, err := infrastructure.OpenAESEnvelope(aesKey, iv, elements[0])
	if err != nil || !bytes.Equal(first, certificate.Raw) {
		t.Fatalf("the page cannot read the AES answer: %v", err)
	}
}

// TestRefusalsAndFailuresReachThePage.
func TestRefusalsAndFailuresReachThePage(t *testing.T) {
	server := afirmaserver.New(t)
	id := sessionID()
	base := "afirma://sign?id=" + id + "&key=12345678&stservlet=" + url.QueryEscape(storage) + "&algorithm=SHA256&dat=aG9sYQ%3D%3D"

	declined, _ := domain.ParseInvocation(base + "&format=CAdES")
	useCase(server, approving{}).Execute(context.Background(), declined)
	if history := server.History(id); history[len(history)-1] != "CANCEL" {
		t.Errorf("a refusal reaches the page as CANCEL: %q", history)
	}

	invalid, _ := domain.ParseInvocation(base + "&format=OOXML")
	useCase(server, approving{}).Execute(context.Background(), invalid)
	if history := server.History(id); history[len(history)-1] != "SAF_06: Formato de firma no soportado" {
		t.Errorf("a failure reaches the page readable: %q", history[len(history)-1])
	}

	missing, _ := domain.ParseInvocation("afirma://sign?fileid=" + sessionID() + "&rtservlet=" + url.QueryEscape(retrieve) + "&key=12345678")
	_, err := useCase(server, approving{}).Execute(context.Background(), missing)
	if err == nil || !strings.Contains(err.Error(), "SAF_16") {
		t.Errorf("an unknown file id is SAF_16: %v", err)
	}
}
