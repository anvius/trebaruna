package cli_test

// A WebSocket session through `trebaruna afirma --interactive`, as the
// window drives it: the page's requests arrive on the socket, each
// proposal goes to the window and each decision comes back on stdin. With
// sticky, the second request offers the key approved for the first.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/localtls"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/websocket"
	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
)

func TestASessionOffersTheKeyThePageAskedToKeep(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	directory, err := localtls.Directory()
	if err != nil {
		t.Fatal(err)
	}
	material, err := localtls.Generate(directory, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key := writeIdentityP12(t, "segreto", "MARIA GARCIA", 35)
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	port := strconv.Itoa(free.Addr().(*net.TCPAddr).Port)
	free.Close()

	decisions, decide := io.Pipe()
	printed, output := io.Pipe()
	exited := make(chan int, 1)
	go func() {
		exited <- cli.RunIO([]string{"afirma", "afirma://websocket?ports=" + port + "&v=4&idsession=Sesion1", "--interactive"},
			decisions, output, io.Discard)
		output.Close()
	}()
	lines := bufio.NewScanner(printed)
	next := func() map[string]any {
		t.Helper()
		if !lines.Scan() {
			t.Fatal("the command printed nothing more")
		}
		var line map[string]any
		if err := json.Unmarshal(lines.Bytes(), &line); err != nil {
			t.Fatalf("not a JSON line: %q", lines.Text())
		}
		return line
	}
	if listening := next(); listening["type"] != "listening" {
		t.Fatalf("first line %v", listening)
	}

	pool := x509.NewCertPool()
	pool.AddCert(material.Root)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	page, err := websocket.Dial(ctx, "127.0.0.1:"+port, "/", &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	ask := func(document string) chan string {
		answer := make(chan string, 1)
		go func() {
			_ = page.WriteText("afirma://sign?op=sign&idsession=Sesion1&format=CAdES&algorithm=SHA256withRSA&sticky=true&appname=sede.example" +
				"&dat=" + base64.URLEncoding.EncodeToString([]byte(document)))
			text, _ := page.ReadMessage()
			answer <- text
		}()
		return answer
	}

	first := ask("primera solicitud")
	if proposal := next(); proposal["type"] != "proposal" || proposal["remembered"] != nil {
		t.Fatalf("the first proposal offers no kept key: %v", proposal)
	}
	io.WriteString(decide, `{"approved":true,"key":{"p12":"`+key+`"},"passphrase":"segreto"}`+"\n")
	if outcome := next(); outcome["session"] != true {
		t.Errorf("first outcome %v", outcome)
	}
	firstAnswer := <-first

	second := ask("segunda solicitud")
	if proposal := next(); proposal["remembered"] != "MARIA GARCIA" {
		t.Fatalf("the second proposal offers the kept key: %v", proposal)
	}
	io.WriteString(decide, `{"approved":true,"remembered":true}`+"\n")
	next()
	secondAnswer := <-second

	firstCertificate, _, _ := strings.Cut(firstAnswer, "|")
	secondCertificate, signature, _ := strings.Cut(secondAnswer, "|")
	if firstCertificate == "" || firstCertificate != secondCertificate || signature == "" {
		t.Errorf("the kept key signs the second request: %q then %q", firstAnswer, secondAnswer)
	}

	page.Close()
	if closed := next(); closed["type"] != "closed" {
		t.Errorf("last line %v", closed)
	}
	if code := <-exited; code != 0 {
		t.Errorf("exit %d", code)
	}
}
