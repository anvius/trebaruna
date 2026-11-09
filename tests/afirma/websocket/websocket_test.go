package websocket_test

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/websocket"
)

// echoServer answers each message with its reverse, until the peer closes.
func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request)
		if err != nil {
			return
		}
		defer connection.Close()
		for {
			message, err := connection.ReadMessage()
			if err != nil {
				return
			}
			runes := []rune(message)
			for left, right := 0, len(runes)-1; left < right; left, right = left+1, right-1 {
				runes[left], runes[right] = runes[right], runes[left]
			}
			if connection.WriteText(string(runes)) != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestMessagesOfEverySizeGoBothWays: short, 16-bit and 64-bit lengths.
func TestMessagesOfEverySizeGoBothWays(t *testing.T) {
	server := echoServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := websocket.Dial(ctx, strings.TrimPrefix(server.URL, "http://"), "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	for _, size := range []int{0, 5, 125, 126, 65535, 65536, 3 << 20} {
		message := strings.Repeat("ab", size/2) + strings.Repeat("c", size%2)
		if err := connection.WriteText(message + "é"); err != nil {
			t.Fatal(err)
		}
		answer, err := connection.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if len(answer) != len(message)+len("é") || !strings.HasPrefix(answer, "é") {
			t.Errorf("size %d: answer of %d bytes", size, len(answer))
		}
	}
}

// TestTheHandshakeFollowsTheRFC: the accept value is the RFC's example's,
// and a request that is no handshake is refused.
func TestTheHandshakeFollowsTheRFC(t *testing.T) {
	server := echoServer(t)
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha1.Sum([]byte("dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(digest[:]) ||
		response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("%s %v", response.Status, response.Header)
	}
	response.Body.Close()
	plain, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if plain.StatusCode != http.StatusBadRequest {
		t.Errorf("a plain request: %s", plain.Status)
	}
	plain.Body.Close()
}

// TestClosingEndsTheConversation.
func TestClosingEndsTheConversation(t *testing.T) {
	closed := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request)
		if err != nil {
			return
		}
		_, err = connection.ReadMessage()
		closed <- err
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := websocket.Dial(ctx, strings.TrimPrefix(server.URL, "http://"), "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	select {
	case err := <-closed:
		if err != io.EOF {
			t.Errorf("the server read %v, want EOF", err)
		}
	case <-ctx.Done():
		t.Fatal("the close was not seen")
	}
}
