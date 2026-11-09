package domain

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
)

// ParseRequestXML reads the request a page uploaded to the intermediate
// server (C.3): a root named after the operation ("op" meaning sign), one
// <e k="…" v="…"/> per parameter with URL-encoded values, and a child op
// overriding the root. External entities are never resolved.
func ParseRequestXML(document []byte) (Invocation, error) {
	decoder := xml.NewDecoder(bytes.NewReader(document))
	decoder.Strict = true
	decoder.Entity = map[string]string{}

	var root string
	params := map[string]string{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Invocation{}, Failure{Code: Params, Cause: "unreadable request XML"}
		}
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if root == "" {
			root = element.Name.Local
			continue
		}
		if element.Name.Local != "e" {
			return Invocation{}, Failure{Code: Params, Cause: "request XML with an element other than e"}
		}
		var key, value string
		for _, attribute := range element.Attr {
			switch attribute.Name.Local {
			case "k":
				key = attribute.Value
			case "v":
				value = attribute.Value
			}
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			decoded = value
		}
		if key != "" {
			params[key] = decoded
		}
	}
	return invocationFrom(root, params)
}

// ParseRequestJSON reads the JSON variant {"params":[{"k":…,"v":…}]} (C.3).
func ParseRequestJSON(document []byte, operation Operation) (Invocation, error) {
	var parsed struct {
		Params []struct {
			K string `json:"k"`
			V string `json:"v"`
		} `json:"params"`
	}
	if err := json.Unmarshal(document, &parsed); err != nil {
		return Invocation{}, Failure{Code: Params, Cause: "unreadable request JSON"}
	}
	params := map[string]string{}
	for _, param := range parsed.Params {
		decoded, err := url.QueryUnescape(param.V)
		if err != nil {
			decoded = param.V
		}
		params[param.K] = decoded
	}
	return invocationFrom(string(operation), params)
}

// invocationFrom names the operation from the root or the op parameter.
func invocationFrom(root string, params map[string]string) (Invocation, error) {
	name := strings.ToLower(root)
	if op := params["op"]; op != "" {
		name = strings.ToLower(op)
	}
	if name == "op" {
		name = string(Sign)
	}
	for _, operation := range dispatchOrder {
		if string(operation) == name {
			return InvocationOf(operation, params), nil
		}
	}
	return Invocation{}, Failure{Code: UnsupportedOperation}
}
