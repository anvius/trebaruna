package infrastructure_test

// The WebSocket channel (D.1) end to end: the page's echo, a signature
// approved by the person and returned on the socket, the session check of
// protocol 4, the asynchronous answers of 4.1, the port fallback and the
// end of the session, over TLS trusted through the local channel's root
// alone (ADR-0019).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/localtls"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/websocket"
	"codeberg.org/simplicer/trebaruna/tests/support/afirmaserver"
)

type channelFixture struct {
	connection *websocket.Conn
	served     chan error
	material   localtls.Material
}

// openChannel serves a channel on a busy port then a free one, and
// connects as the page does.
func openChannel(t *testing.T, channel domain.LocalChannel, approver application.Approver) channelFixture {
	t.Helper()
	material, err := localtls.Generate(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { busy.Close() })
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	freePort := free.Addr().(*net.TCPAddr).Port
	free.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	channel.Ports = []int{busyPort, freePort}

	answers := application.NewAnswerLocalChannel(useCase(afirmaserver.New(t), approver), channel)
	listening := make(chan int, 1)
	served := make(chan error, 1)
	server := infrastructure.LocalServer{Certificate: material.Server, Answer: answers.Answer,
		Listening: func(port int) { listening <- port }, Patience: 10 * time.Second}
	go func() { served <- server.Serve(context.Background(), channel.Ports) }()
	port := <-listening
	if port != freePort {
		t.Fatalf("listening on %d, want the first free port %d", port, freePort)
	}
	pool := x509.NewCertPool()
	pool.AddCert(material.Root)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := websocket.Dial(ctx, "127.0.0.1:"+strconv.Itoa(port), "/", &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	return channelFixture{connection: connection, served: served, material: material}
}

func (f channelFixture) ask(t *testing.T, message string) string {
	t.Helper()
	if err := f.connection.WriteText(message); err != nil {
		t.Fatal(err)
	}
	answer, err := f.connection.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	return answer
}

func signOperation(session, document string) string {
	return "afirma://sign?op=sign&idsession=" + session + "&algorithm=SHA256withRSA&format=CAdES&properties=&appname=sede.example" +
		"&dat=" + base64.URLEncoding.EncodeToString([]byte(document))
}

func TestAPageSignsThroughTheLocalChannel(t *testing.T) {
	maria, certificate := identity(t, "MARIA GARCIA", 61)
	fixture := openChannel(t, domain.LocalChannel{Version: 4, SessionID: "abc123"}, approving{key: maria})

	if answer := fixture.ask(t, "echo=-idsession=abc123@EOF"); answer != "OK" {
		t.Errorf("echo: %q", answer)
	}
	if answer := fixture.ask(t, "echo=-idsession=other@EOF"); !strings.HasPrefix(answer, "SAF_46") {
		t.Errorf("another session: %q", answer)
	}
	answer := fixture.ask(t, signOperation("abc123", "solicitud por websocket"))
	elements := strings.Split(answer, "|")
	if len(elements) != 2 {
		t.Fatalf("the answer is cert|signature: %q", answer)
	}
	if got, _ := base64.URLEncoding.DecodeString(elements[0]); string(got) != string(certificate.Raw) {
		t.Error("the certificate is the signer's")
	}
	if signature, err := base64.URLEncoding.DecodeString(elements[1]); err != nil || len(signature) < 100 {
		t.Errorf("the signature: %v", err)
	}
	if answer := fixture.ask(t, signOperation("other", "x")); !strings.HasPrefix(answer, "SAF_46") {
		t.Errorf("an operation for another session: %q", answer)
	}
	if answer := fixture.ask(t, "afirma://websocket?ports=1&v=4&idsession=abc123"); !strings.HasPrefix(answer, "SAF_04") {
		t.Errorf("a channel inside the channel: %q", answer)
	}

	// Declined: the page hears CANCEL.
	fixture.connection.Close()
	select {
	case err := <-fixture.served:
		if err != nil {
			t.Errorf("the channel ended with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the channel did not end when the page left")
	}
}

func TestADeclinedOperationAnswersCancel(t *testing.T) {
	fixture := openChannel(t, domain.LocalChannel{Version: 3}, approving{})
	if answer := fixture.ask(t, signOperation("", "x")); answer != "CANCEL" {
		t.Errorf("declined: %q", answer)
	}
	fixture.connection.Close()
}

// TestProtocol41AnswersWaitThenTheResult.
func TestProtocol41AnswersWaitThenTheResult(t *testing.T) {
	maria, _ := identity(t, "MARIA GARCIA", 62)
	fixture := openChannel(t, domain.LocalChannel{Version: 4, Asynchronous: true, SessionID: "s41"},
		approving{key: maria, delay: 200 * time.Millisecond})
	if answer := fixture.ask(t, signOperation("s41", "asincrona")); answer != "#wait" {
		t.Fatalf("an operation over 4.1: %q", answer)
	}
	var result string
	for attempt := 0; attempt < 100; attempt++ {
		if result = fixture.ask(t, "getresult?idsession=s41"); result != "#wait" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(strings.Split(result, "|")) != 2 {
		t.Errorf("the result: %q", result)
	}
	if again := fixture.ask(t, "getresult?idsession=s41"); again != "#wait" {
		t.Errorf("a result is given once: %q", again)
	}
	fixture.connection.Close()
}

// TestNoPageMeansTheChannelCloses: without a connection in time, and with
// no port free, the channel says why.
func TestNoPageMeansTheChannelCloses(t *testing.T) {
	material, err := localtls.Generate(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	server := infrastructure.LocalServer{Certificate: material.Server, Answer: func(context.Context, string) string { return "" },
		Patience: 200 * time.Millisecond}
	if err := server.Serve(context.Background(), []int{port}); err != infrastructure.ErrNoPage {
		t.Errorf("without a page: %v", err)
	}
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	err = server.Serve(context.Background(), []int{busy.Addr().(*net.TCPAddr).Port})
	if failure, ok := err.(domain.Failure); !ok || failure.Code != domain.CannotOpenSocket {
		t.Errorf("no port free: %v", err)
	}
}

func TestTheLaunchURINamesTheChannel(t *testing.T) {
	for uri, want := range map[string]domain.LocalChannel{
		"afirma://websocket?ports=50001,-50002&v=4&jvc=3&idsession=Ab12": {Ports: []int{50001, 50002}, Version: 4, SessionID: "Ab12"},
		"afirma://websocket?ports=50001&v=4&jvc=4&idsession=Ab12":        {Ports: []int{50001}, Version: 4, Asynchronous: true, SessionID: "Ab12"},
		"afirma://websocket?v=3&idsession=Ab12":                          {Ports: []int{63117}, Version: 3, SessionID: "Ab12"},
	} {
		invocation, err := domain.ParseInvocation(uri)
		if err != nil {
			t.Fatal(err)
		}
		got, err := domain.ReadLocalChannel(invocation)
		if err != nil || got.Version != want.Version || got.Asynchronous != want.Asynchronous || got.SessionID != want.SessionID ||
			len(got.Ports) != len(want.Ports) || got.Ports[0] != want.Ports[0] {
			t.Errorf("%s: %+v %v", uri, got, err)
		}
	}
	for _, uri := range []string{"afirma://websocket?ports=50001&v=5", "afirma://websocket?ports=abc&v=4", "afirma://websocket?ports=1&v=4&idsession=no-dashes!"} {
		invocation, _ := domain.ParseInvocation(uri)
		if _, err := domain.ReadLocalChannel(invocation); err == nil {
			t.Errorf("%s was accepted", uri)
		}
	}
	if session := domain.MessageSession("echo=-idsession=XyZ@EOF"); session != "XyZ" {
		t.Errorf("echo session %q", session)
	}
	if session := domain.MessageSession("afirma://sign?op=sign&idsession=XyZ&dat=AAA"); session != "XyZ" {
		t.Errorf("operation session %q", session)
	}
}

// TestAConnectionThatSaysNothingDoesNotHoldTheChannel: a connection that
// opens and stays silent, or names another session, does not take the
// session; the page's connection does, and the channel ends with it.
func TestAConnectionThatSaysNothingDoesNotHoldTheChannel(t *testing.T) {
	maria, _ := identity(t, "MARIA GARCIA", 63)
	fixture := openChannel(t, domain.LocalChannel{Version: 4, SessionID: "page1"}, approving{key: maria})
	// fixture.connection is the silent one; the page connects next.
	pool := x509.NewCertPool()
	pool.AddCert(fixture.material.Root)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	address := fixture.connection.RemoteAddr().String()
	stranger, err := websocket.Dial(ctx, address, "/", &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	if err := stranger.WriteText("echo=-idsession=other@EOF"); err != nil {
		t.Fatal(err)
	}
	if answer, _ := stranger.ReadMessage(); !strings.HasPrefix(answer, "SAF_46") {
		t.Errorf("another session: %q", answer)
	}
	page, err := websocket.Dial(ctx, address, "/", &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	if err := page.WriteText("echo=-idsession=page1@EOF"); err != nil {
		t.Fatal(err)
	}
	if answer, _ := page.ReadMessage(); answer != "OK" {
		t.Errorf("the page's echo: %q", answer)
	}
	page.Close()
	select {
	case err := <-fixture.served:
		if err != nil {
			t.Errorf("the channel ended with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the channel stayed open after the page left, held by a silent connection")
	}
	fixture.connection.Close()
	stranger.Close()
}
