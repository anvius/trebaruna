package afirmaserver

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// BatchOutcome records what the post-signer verified, for the test.
type BatchOutcome struct {
	Verified    []string
	Failed      []string
	PostedBatch []byte
	PREKept     map[string]bool
}

// EnableBatches adds JSON and XML pre- and post-signers at
// /JSONBatchPresigner, /JSONBatchPostsigner, /XMLBatchPresigner and
// /XMLBatchPostsigner. The pre-signer prepares random bytes as each
// pre-signature (asking to keep PRE for item ids starting "keep") and reports
// items whose reference is "unprepared" as ERROR_PRE; the post-signer checks
// every PK1 against its PRE with the certificate it received.
func (s *Server) EnableBatches() *BatchOutcome {
	outcome := &BatchOutcome{PREKept: map[string]bool{}}
	pres := map[string][]byte{}
	mux := s.server.Config.Handler.(*http.ServeMux)

	mux.HandleFunc("/JSONBatchPresigner", func(writer http.ResponseWriter, request *http.Request) {
		values := params(request)
		batch, _ := base64.URLEncoding.DecodeString(values["json"])
		var parsed struct {
			Format      string `json:"format"`
			SingleSigns []struct {
				ID            string `json:"id"`
				DataReference string `json:"datareference"`
			} `json:"singlesigns"`
		}
		json.Unmarshal(batch, &parsed)
		var infos, results []map[string]any
		for _, item := range parsed.SingleSigns {
			if item.DataReference == "unprepared" {
				results = append(results, map[string]any{"id": item.ID, "result": "ERROR_PRE", "description": "no such document"})
				continue
			}
			pre := make([]byte, 48)
			rand.Read(pre)
			s.mutex.Lock()
			pres[item.ID] = pre
			s.mutex.Unlock()
			params := map[string]string{"PRE": base64.StdEncoding.EncodeToString(pre), "TIME": "1731150000000"}
			if strings.HasPrefix(item.ID, "keep") {
				params["NEED_PRE"] = "true"
			}
			infos = append(infos, map[string]any{"id": item.ID, "signid": "sig-" + item.ID, "params": params})
		}
		answer := map[string]any{"td": map[string]any{"format": parsed.Format, "signs": []any{map[string]any{"signinfo": infos}}}}
		if len(results) > 0 {
			answer["results"] = results
		}
		json.NewEncoder(writer).Encode(answer)
	})

	mux.HandleFunc("/JSONBatchPostsigner", func(writer http.ResponseWriter, request *http.Request) {
		values := params(request)
		batch, _ := base64.URLEncoding.DecodeString(values["json"])
		triphase, _ := base64.URLEncoding.DecodeString(values["tridata"])
		var data struct {
			SignInfo []struct {
				ID     string            `json:"id"`
				Params map[string]string `json:"params"`
			} `json:"signinfo"`
		}
		json.Unmarshal(triphase, &data)
		certificate := firstCertificate(values["certs"])
		var signs []map[string]any
		s.mutex.Lock()
		outcome.PostedBatch = batch
		for _, info := range data.SignInfo {
			_, kept := info.Params["PRE"]
			outcome.PREKept[info.ID] = kept
			if verifies(certificate, pres[info.ID], info.Params["PK1"]) {
				outcome.Verified = append(outcome.Verified, info.ID)
				signs = append(signs, map[string]any{"id": info.ID, "result": "DONE_AND_SAVED"})
			} else {
				outcome.Failed = append(outcome.Failed, info.ID)
				signs = append(signs, map[string]any{"id": info.ID, "result": "ERROR_POST", "description": "bad signature"})
			}
		}
		s.mutex.Unlock()
		json.NewEncoder(writer).Encode(map[string]any{"signs": signs})
	})

	mux.HandleFunc("/XMLBatchPresigner", func(writer http.ResponseWriter, request *http.Request) {
		values := params(request)
		batch, _ := base64.URLEncoding.DecodeString(values["xml"])
		var parsed struct {
			Items []struct {
				ID string `xml:"Id,attr"`
			} `xml:"singlesign"`
		}
		xml.Unmarshal(batch, &parsed)
		var builder strings.Builder
		builder.WriteString(`<xml><firmas format="CAdES">`)
		for _, item := range parsed.Items {
			pre := make([]byte, 40)
			rand.Read(pre)
			s.mutex.Lock()
			pres[item.ID] = pre
			s.mutex.Unlock()
			fmt.Fprintf(&builder, `<firma Id="%s" signid="s-%s"><param n="PRE">%s</param></firma>`, item.ID, item.ID, base64.StdEncoding.EncodeToString(pre))
		}
		builder.WriteString(`</firmas></xml>`)
		io.WriteString(writer, builder.String())
	})

	mux.HandleFunc("/XMLBatchPostsigner", func(writer http.ResponseWriter, request *http.Request) {
		values := params(request)
		triphase, _ := base64.URLEncoding.DecodeString(values["tridata"])
		var data struct {
			Firmas struct {
				Firma []struct {
					ID     string `xml:"Id,attr"`
					Params []struct {
						Name  string `xml:"n,attr"`
						Value string `xml:",chardata"`
					} `xml:"param"`
				} `xml:"firma"`
			} `xml:"firmas"`
		}
		xml.Unmarshal(triphase, &data)
		certificate := firstCertificate(values["certs"])
		var builder strings.Builder
		builder.WriteString("<signs>")
		s.mutex.Lock()
		for _, firma := range data.Firmas.Firma {
			pk1 := ""
			for _, param := range firma.Params {
				if param.Name == "PK1" {
					pk1 = param.Value
				}
			}
			result := "ERROR_POST"
			if verifies(certificate, pres[firma.ID], pk1) {
				result = "DONE_AND_SAVED"
				outcome.Verified = append(outcome.Verified, firma.ID)
			}
			fmt.Fprintf(&builder, `<signresult id="%s" result="%s" description=""/>`, firma.ID, result)
		}
		s.mutex.Unlock()
		builder.WriteString("</signs>")
		io.WriteString(writer, builder.String())
	})
	return outcome
}

// firstCertificate reads the signer's certificate from certs=a;b;c.
func firstCertificate(certs string) *x509.Certificate {
	first, _, _ := strings.Cut(certs, ";")
	raw, err := base64.URLEncoding.DecodeString(first)
	if err != nil {
		return nil
	}
	certificate, _ := x509.ParseCertificate(raw)
	return certificate
}

// verifies checks PK1 over PRE with SHA-256, RSA or ECDSA.
func verifies(certificate *x509.Certificate, pre []byte, pk1 string) bool {
	signature, err := base64.StdEncoding.DecodeString(pk1)
	if certificate == nil || err != nil || len(pre) == 0 {
		return false
	}
	algorithm := x509.SHA256WithRSA
	switch certificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		algorithm = x509.ECDSAWithSHA256
	case *rsa.PublicKey:
	}
	return certificate.CheckSignature(algorithm, pre, signature) == nil
}
