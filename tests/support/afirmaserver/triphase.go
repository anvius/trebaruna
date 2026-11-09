package afirmaserver

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
)

// TriphaseOutcome records what the single-signature service received.
type TriphaseOutcome struct {
	// Calls are the form fields of each call, in order.
	Calls []map[string]string
	// Verified reports a PK1 that is the signature of the PRE prepared.
	Verified bool
}

// EnableTriphase adds a single-signature triphase service at
// /TriPhaseSignerServer (E.8): pre prepares random bytes as the
// pre-signature of document doc, or for NONE the document itself, as
// AutoFirma's Pkcs1TriPhasePreProcessor does (a document "swap" gets the
// random bytes, as a dishonest server would give); post checks PK1 against
// them with the first certificate it received, and answers with the new id
// "signed-<doc>". A document id "refuse" is answered ERR-11.
func (s *Server) EnableTriphase() *TriphaseOutcome {
	outcome := &TriphaseOutcome{}
	random := make([]byte, 32)
	rand.Read(random)
	presignature := func(format string, document []byte) []byte {
		if format == "NONE" && string(document) != "swap" {
			return document
		}
		return random
	}
	mux := s.server.Config.Handler.(*http.ServeMux)
	mux.HandleFunc("/TriPhaseSignerServer", func(writer http.ResponseWriter, request *http.Request) {
		values := params(request)
		outcome.Calls = append(outcome.Calls, values)
		document, _ := base64.URLEncoding.DecodeString(values["doc"])
		if string(document) == "refuse" {
			fmt.Fprint(writer, "ERR-11: the document is not available")
			return
		}
		pre := presignature(values["format"], document)
		switch values["op"] {
		case "pre":
			data := `<xml><firmas format="` + values["format"] + `"><firma Id="` + string(document) + `">` +
				`<param n="PRE">` + base64.StdEncoding.EncodeToString(pre) + `</param></firma></firmas></xml>`
			fmt.Fprint(writer, base64.URLEncoding.EncodeToString([]byte(data)))
		case "post":
			session, _ := base64.URLEncoding.DecodeString(values["session"])
			var parsed struct {
				Firmas struct {
					Firma []struct {
						Params []struct {
							Name  string `xml:"n,attr"`
							Value string `xml:",chardata"`
						} `xml:"param"`
					} `xml:"firma"`
				} `xml:"firmas"`
			}
			xml.Unmarshal(session, &parsed)
			first, _, _ := strings.Cut(values["cert"], ",")
			raw, _ := base64.URLEncoding.DecodeString(first)
			certificate, _ := x509.ParseCertificate(raw)
			for _, firma := range parsed.Firmas.Firma {
				for _, param := range firma.Params {
					if param.Name == "PK1" && verifies(certificate, pre, param.Value) {
						outcome.Verified = true
					}
				}
			}
			fmt.Fprint(writer, "OK NEWID="+base64.URLEncoding.EncodeToString([]byte("signed-"+string(document))))
		}
	})
	return outcome
}
