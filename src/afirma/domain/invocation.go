// Package domain holds the rules of AutoFirma's afirma:// protocol as
// docs/afirma-protocol.md specifies them: how a page's request is read, what
// it may ask, and how the answer is written. It knows nothing about HTTP,
// windows or keys.
package domain

import (
	"net/url"
	"strings"
)

// Operation is what a page asks for: the URI's host.
type Operation string

const (
	Sign        Operation = "sign"
	Cosign      Operation = "cosign"
	Countersign Operation = "countersign"
	SignAndSave Operation = "signandsave"
	SelectCert  Operation = "selectcert"
	Save        Operation = "save"
	Load        Operation = "load"
	Batch       Operation = "batch"
	WebSocket   Operation = "websocket"
	Service     Operation = "service"
)

// dispatchOrder lists the operations in the order AutoFirma tries their
// prefixes; each is matched as "afirma://<op>?" or "afirma://<op>/?" (A.1).
var dispatchOrder = []Operation{WebSocket, Service, Batch, SelectCert, Save, SignAndSave, Sign, Cosign, Countersign, Load}

// Invocation is a parsed afirma:// URI.
type Invocation struct {
	Operation Operation
	params    map[string]string
}

// ParseInvocation reads a URI the way AutoFirma 1.9 does (A.1, A.2): the
// literal, case-sensitive "afirma://" prefix, the operation as the host
// followed by "?" or "/?", then the query after the first "?", split on "&",
// each piece at its first "=", values form-decoded, the last duplicate
// winning. A query parameter "op" never selects the operation.
func ParseInvocation(uri string) (Invocation, error) {
	if uri == "" {
		return Invocation{}, Failure{Code: NullURI}
	}
	if !strings.HasPrefix(uri, "afirma://") {
		return Invocation{}, Failure{Code: UnsupportedProtocol}
	}
	for _, operation := range dispatchOrder {
		prefix := "afirma://" + string(operation)
		if strings.HasPrefix(uri, prefix+"?") || strings.HasPrefix(uri, prefix+"/?") {
			params, err := parseQuery(uri)
			if err != nil {
				return Invocation{}, err
			}
			return Invocation{Operation: operation, params: params}, nil
		}
	}
	return Invocation{}, Failure{Code: UnsupportedOperation}
}

// InvocationOf builds an invocation from parameters already read, as the
// intermediate server's XML delivers them (C.3).
func InvocationOf(operation Operation, params map[string]string) Invocation {
	copied := make(map[string]string, len(params))
	for key, value := range params {
		copied[key] = value
	}
	return Invocation{Operation: operation, params: copied}
}

// parseQuery applies A.2 to everything after the first "?".
func parseQuery(uri string) (map[string]string, error) {
	query := uri
	if at := strings.Index(uri, "?"); at >= 0 {
		query = uri[at+1:]
	}
	params := map[string]string{}
	for _, piece := range strings.Split(query, "&") {
		at := strings.Index(piece, "=")
		if at <= 0 {
			continue
		}
		value, err := url.QueryUnescape(piece[at+1:])
		if err != nil {
			return nil, Failure{Code: Params, Cause: "undecodable value for " + piece[:at]}
		}
		params[piece[:at]] = value
	}
	return params, nil
}

// Param returns a parameter, empty when absent.
func (i Invocation) Param(name string) string { return i.params[name] }

// Has reports whether a parameter is present, even empty.
func (i Invocation) Has(name string) bool {
	_, present := i.params[name]
	return present
}

// Names lists the parameters present, for showing a request in full.
func (i Invocation) Names() []string {
	names := make([]string, 0, len(i.params))
	for name := range i.params {
		names = append(names, name)
	}
	return names
}
