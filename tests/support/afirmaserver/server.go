// Package afirmaserver is a site's intermediate server for tests: the
// StorageService and RetrieveService of AutoFirma's protocol, behaving as
// docs/afirma-protocol.md (C.9) describes — form bodies split on "&" and the
// first "=", dat URL-decoded, one read per stored item with a trailing
// newline, "OK" without one, items expiring after a minute.
package afirmaserver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Server is a running intermediate server.
type Server struct {
	mutex   sync.Mutex
	stored  map[string]item
	history map[string][]string
	server  *httptest.Server
}

type item struct {
	data string
	at   time.Time
}

// expiry is the default expTime of the servlets.
const expiry = 60 * time.Second

// New starts the server until the test ends.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{stored: map[string]item{}, history: map[string][]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/StorageService", s.storage)
	mux.HandleFunc("/RetrieveService", s.retrieve)
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

// Client reaches the server for any host name, so URLs can name a site
// (http://sede.example/...) that the protocol accepts, unlike 127.0.0.1.
func (s *Server) Client() *http.Client {
	address := s.server.Listener.Addr().String()
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}}
}

// Put stores data under an id, as a page uploading a long request does.
func (s *Server) Put(id, data string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.stored[id] = item{data: data, at: time.Now()}
	s.history[id] = append(s.history[id], data)
}

// History is every value stored under an id, in order.
func (s *Server) History(id string) []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]string{}, s.history[id]...)
}

// Take reads an id the way the page's polling does: once.
func (s *Server) Take(id string) (string, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	stored, ok := s.stored[id]
	if !ok || time.Since(stored.at) > expiry {
		return "", false
	}
	delete(s.stored, id)
	return stored.data, true
}

// params splits a form body (or a query) on "&" and the first "=".
func params(request *http.Request) map[string]string {
	raw := request.URL.RawQuery
	if request.Method == http.MethodPost {
		body, _ := io.ReadAll(request.Body)
		raw = string(body)
	}
	values := map[string]string{}
	for _, piece := range strings.Split(raw, "&") {
		key, value, found := strings.Cut(piece, "=")
		if found {
			values[key] = value
		}
	}
	return values
}

func (s *Server) storage(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	values := params(request)
	switch {
	case values["op"] == "":
		io.WriteString(writer, "ERR-00:=no operation")
	case values["v"] == "":
		io.WriteString(writer, "ERR-20:=no syntax version")
	case values["op"] == "check":
		io.WriteString(writer, "OK")
	case values["op"] != "put":
		io.WriteString(writer, "ERR-01:=unsupported operation")
	case values["id"] == "":
		io.WriteString(writer, "ERR-05:=no id")
	case values["dat"] == "":
		io.WriteString(writer, "ERR-02:=no data")
	default:
		decoded, err := url.QueryUnescape(values["dat"])
		if err != nil {
			io.WriteString(writer, "ERR-07:=invalid data")
			return
		}
		s.Put(values["id"], decoded)
		io.WriteString(writer, "OK")
	}
}

func (s *Server) retrieve(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	values := params(request)
	switch {
	case values["op"] != "get":
		io.WriteString(writer, "ERR-01:=unsupported operation\n")
	case values["v"] == "":
		io.WriteString(writer, "ERR-20:=no syntax version\n")
	default:
		data, ok := s.Take(values["id"])
		if !ok {
			io.WriteString(writer, "ERR-06:=no data for this id\n")
			return
		}
		io.WriteString(writer, data+"\n")
	}
}
