package infrastructure

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure/websocket"
)

// LocalServer serves a page's WebSocket channel (D.1): TLS on the first of
// the page's ports it can bind, on 127.0.0.1 alone, with the local
// channel's certificate (ADR-0019). Each message is answered in turn; the
// server stops when the connection that took the session closes, as
// AutoFirma's does with the page's, or when no page speaks within Patience.
type LocalServer struct {
	Certificate tls.Certificate
	// Answer answers one message of the page.
	Answer func(ctx context.Context, message string) string
	// Listening hears the port bound, once.
	Listening func(port int)
	Patience  time.Duration
}

// ErrNoPage means no page connected in time.
var ErrNoPage = errors.New("no page connected to the local channel")

// Serve binds, serves the page and returns when it has gone.
func (s LocalServer) Serve(ctx context.Context, ports []int) error {
	var listener net.Listener
	var port int
	for _, candidate := range ports {
		bound, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(candidate)))
		if err == nil {
			listener, port = bound, candidate
			break
		}
	}
	if listener == nil {
		return domain.Failure{Code: domain.CannotOpenSocket, Cause: fmt.Sprint(ports)}
	}
	if s.Listening != nil {
		s.Listening(port)
	}

	// The session is the first connection's that sends a message for it (a
	// connection that only opens, or names another session, claims
	// nothing): when that connection ends, the channel ends.
	served := make(chan struct{})
	var state sync.Mutex
	claimed := false
	claim := func() bool {
		state.Lock()
		defer state.Unlock()
		if claimed {
			return false
		}
		claimed = true
		return true
	}
	server := &http.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{s.Certificate}, MinVersion: tls.VersionTLS12},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			connection, err := websocket.Accept(writer, request)
			if err != nil {
				return
			}
			defer connection.Close()
			if host, _, _ := net.SplitHostPort(request.RemoteAddr); host != "127.0.0.1" {
				_ = connection.WriteText(domain.Failure{Code: domain.ExternalRequest}.Answer())
				return
			}
			owner := false
			defer func() {
				if owner {
					close(served)
				}
			}()
			for {
				message, err := connection.ReadMessage()
				if err != nil {
					return
				}
				answer := s.Answer(ctx, message)
				if !owner && !strings.HasPrefix(answer, "SAF_46") {
					owner = claim()
				}
				if err := connection.WriteText(answer); err != nil {
					return
				}
			}
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	defer server.Close()

	patience := s.Patience
	if patience == 0 {
		patience = 2 * time.Minute
	}
	waiting := time.NewTimer(patience)
	defer waiting.Stop()
	for {
		select {
		case <-served:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-waiting.C:
			state.Lock()
			connected := claimed
			state.Unlock()
			if !connected {
				return ErrNoPage
			}
		}
	}
}
