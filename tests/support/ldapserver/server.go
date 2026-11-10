// Package ldapserver is an LDAP directory for tests: it answers an
// anonymous bind and searches by mail or cn over the entries it holds,
// optionally over TLS, and records what it was asked. It reads requests
// with encoding/asn1, not with trebaruna's own LDAP encoder, so it also
// judges that encoder.
package ldapserver

import (
	"bytes"
	"crypto/tls"
	"encoding/asn1"
	"net"
	"sync"
	"testing"
)

// Entry is a person the directory publishes.
type Entry struct {
	DN, Mail, CN string
	// Attribute is the certificates' attribute name; empty is
	// userCertificate;binary.
	Attribute    string
	Certificates [][]byte
}

// Search is one search the directory was asked.
type Search struct {
	Base       string
	Scope      int
	Values     []string // the filter's assertion values, in order
	Attributes []string
}

// Server is a running directory.
type Server struct {
	// Address is host:port.
	Address string
	// BindResult and SearchResult are the result codes answered; 0 is
	// success.
	BindResult, SearchResult int

	mu       sync.Mutex
	entries  []Entry
	searches []Search
	binds    int
	unbinds  int
}

// Start serves the entries on 127.0.0.1, over TLS when secured is given.
func Start(t *testing.T, secured *tls.Config, entries ...Entry) *Server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if secured != nil {
		listener = tls.NewListener(listener, secured)
	}
	server := &Server{Address: listener.Addr().String(), entries: entries}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(connection)
		}
	}()
	return server
}

// Searches, Binds and Unbinds are what the directory was asked so far.
func (s *Server) Searches() []Search {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Search{}, s.searches...)
}

func (s *Server) Binds() int   { s.mu.Lock(); defer s.mu.Unlock(); return s.binds }
func (s *Server) Unbinds() int { s.mu.Lock(); defer s.mu.Unlock(); return s.unbinds }

type message struct {
	ID        int
	Operation asn1.RawValue
}

type searchRequest struct {
	Base       []byte
	Scope      asn1.Enumerated
	Deref      asn1.Enumerated
	Size, Time int
	TypesOnly  bool
	Filter     asn1.RawValue
	Attributes [][]byte
}

func (s *Server) serve(connection net.Conn) {
	defer connection.Close()
	var buffer []byte
	chunk := make([]byte, 4096)
	for {
		var request message
		rest, err := asn1.Unmarshal(buffer, &request)
		if err != nil {
			read, readErr := connection.Read(chunk)
			if readErr != nil {
				return
			}
			buffer = append(buffer, chunk[:read]...)
			continue
		}
		buffer = rest
		if request.Operation.Class != asn1.ClassApplication {
			return
		}
		switch request.Operation.Tag {
		case 0: // bind
			s.mu.Lock()
			s.binds++
			s.mu.Unlock()
			connection.Write(reply(request.ID, 1, result(s.BindResult)))
		case 2: // unbind
			s.mu.Lock()
			s.unbinds++
			s.mu.Unlock()
			return
		case 3: // search
			var search searchRequest
			if _, err := asn1.UnmarshalWithParams(request.Operation.FullBytes, &search, "application,tag:3"); err != nil {
				return
			}
			recorded := Search{Base: string(search.Base), Scope: int(search.Scope), Values: assertionValues(search.Filter.FullBytes)}
			for _, attribute := range search.Attributes {
				recorded.Attributes = append(recorded.Attributes, string(attribute))
			}
			s.mu.Lock()
			s.searches = append(s.searches, recorded)
			entries := append([]Entry{}, s.entries...)
			s.mu.Unlock()
			for _, entry := range entries {
				if matches(entry, recorded.Values) {
					connection.Write(reply(request.ID, 4, entryBody(entry)))
				}
			}
			connection.Write(reply(request.ID, 5, result(s.SearchResult)))
		}
	}
}

// assertionValues are the values of the equality matches in an OR filter.
func assertionValues(filter []byte) []string {
	var or asn1.RawValue
	if _, err := asn1.Unmarshal(filter, &or); err != nil || or.Class != asn1.ClassContextSpecific || or.Tag != 1 {
		return nil
	}
	var values []string
	for rest := or.Bytes; len(rest) > 0; {
		var equality asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &equality); err != nil || equality.Tag != 3 {
			return nil
		}
		var attribute, value []byte
		after, err := asn1.Unmarshal(equality.Bytes, &attribute)
		if err != nil {
			return nil
		}
		if _, err := asn1.Unmarshal(after, &value); err != nil {
			return nil
		}
		values = append(values, string(attribute)+"="+string(value))
	}
	return values
}

func matches(entry Entry, values []string) bool {
	for _, value := range values {
		if value == "mail="+entry.Mail || value == "cn="+entry.CN {
			return true
		}
	}
	return false
}

func entryBody(entry Entry) []byte {
	attribute := entry.Attribute
	if attribute == "" {
		attribute = "userCertificate;binary"
	}
	partial, _ := asn1.Marshal(struct {
		Type   []byte
		Values [][]byte `asn1:"set"`
	}{[]byte(attribute), entry.Certificates})
	mail, _ := asn1.Marshal(struct {
		Type   []byte
		Values [][]byte `asn1:"set"`
	}{[]byte("mail"), [][]byte{[]byte(entry.Mail)}})
	name, _ := asn1.Marshal([]byte(entry.DN))
	list, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(mail, partial...)})
	return append(name, list...)
}

func result(code int) []byte {
	encoded, _ := asn1.Marshal(asn1.Enumerated(code))
	empty, _ := asn1.Marshal([]byte{})
	return bytes.Join([][]byte{encoded, empty, empty}, nil)
}

func reply(id, operation int, body []byte) []byte {
	encoded, _ := asn1.Marshal(message{ID: id, Operation: asn1.RawValue{Class: asn1.ClassApplication, Tag: operation, IsCompound: true, Bytes: body}})
	return encoded
}
