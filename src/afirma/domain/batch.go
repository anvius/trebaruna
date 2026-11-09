package domain

import (
	"encoding/json"
	"encoding/xml"
	"strings"
)

// BatchRequest is afirma://batch (A.6, E.1).
type BatchRequest struct {
	Common
	PresignURL  string
	PostsignURL string
	// Definition is the batch the page sent (JSON or XML), opaque to the
	// client except for its algorithm and, for the person, its items.
	Definition      []byte
	JSON            bool
	Local           bool
	NeedCertificate bool
}

// ReadBatchRequest validates a batch request.
func ReadBatchRequest(invocation Invocation, servicesRequired bool) (BatchRequest, error) {
	common, err := ReadCommon(invocation, servicesRequired)
	if err != nil {
		return BatchRequest{}, err
	}
	request := BatchRequest{
		Common: common, JSON: invocation.Param("jsonbatch") == "true",
		Local: invocation.Param("localBatchProcess") == "true", NeedCertificate: invocation.Param("needcert") == "true",
	}
	if !request.Local {
		for _, name := range []string{"batchpresignerurl", "batchpostsignerurl"} {
			value := invocation.Param(name)
			if value == "" {
				return BatchRequest{}, Failure{Code: Params, Cause: name + " is required"}
			}
			if err := ValidServletURL(value); err != nil {
				return BatchRequest{}, err
			}
		}
		request.PresignURL, request.PostsignURL = invocation.Param("batchpresignerurl"), invocation.Param("batchpostsignerurl")
	}
	if request.Local && !request.JSON {
		return BatchRequest{}, Failure{Code: Params, Cause: "a local batch must be JSON"}
	}
	definition, err := DecodeBase64(invocation.Param("dat"))
	if err != nil || len(definition) == 0 {
		return BatchRequest{}, Failure{Code: Params, Cause: "the batch definition is missing or not Base64"}
	}
	request.Definition = definition
	return request, nil
}

// BatchItem is one document of a batch, as the person is shown it.
type BatchItem struct {
	ID           string
	Format       string
	Suboperation string
	// Reference is the server's reference (a digest, an id) or, in a local
	// batch, the data itself in Base64.
	Reference string
}

// BatchDefinition is what the client reads of a batch.
type BatchDefinition struct {
	Algorithm    string
	Format       string
	Suboperation string
	StopOnError  bool
	Items        []BatchItem
	// ExtraParams are the batch's default properties, Base64.
	ExtraParams string
}

// ReadBatchDefinition reads the algorithm (which the client must find, E.2)
// and the items.
func ReadBatchDefinition(definition []byte, isJSON bool) (BatchDefinition, error) {
	if isJSON {
		var parsed struct {
			StopOnError  bool   `json:"stoponerror"`
			Algorithm    string `json:"algorithm"`
			Format       string `json:"format"`
			Suboperation string `json:"suboperation"`
			ExtraParams  string `json:"extraparams"`
			SingleSigns  []struct {
				ID            string `json:"id"`
				DataReference string `json:"datareference"`
				Format        string `json:"format"`
				Suboperation  string `json:"suboperation"`
			} `json:"singlesigns"`
		}
		if err := json.Unmarshal(definition, &parsed); err != nil || parsed.Algorithm == "" {
			return BatchDefinition{}, Failure{Code: Params, Cause: "the JSON batch has no algorithm"}
		}
		result := BatchDefinition{Algorithm: parsed.Algorithm, Format: parsed.Format, Suboperation: parsed.Suboperation,
			StopOnError: parsed.StopOnError, ExtraParams: parsed.ExtraParams}
		for _, item := range parsed.SingleSigns {
			result.Items = append(result.Items, BatchItem{ID: item.ID, Format: firstNonEmpty(item.Format, parsed.Format),
				Suboperation: firstNonEmpty(item.Suboperation, parsed.Suboperation, "sign"), Reference: item.DataReference})
		}
		return result, nil
	}

	var parsed struct {
		XMLName     xml.Name `xml:"signbatch"`
		Algorithm   string   `xml:"algorithm,attr"`
		StopOnError string   `xml:"stoponerror,attr"`
		Items       []struct {
			ID           string `xml:"Id,attr"`
			DataSource   string `xml:"datasource"`
			Format       string `xml:"format"`
			Suboperation string `xml:"suboperation"`
		} `xml:"singlesign"`
	}
	if err := xml.Unmarshal(definition, &parsed); err != nil || parsed.Algorithm == "" {
		return BatchDefinition{}, Failure{Code: Params, Cause: "the XML batch has no signbatch algorithm"}
	}
	result := BatchDefinition{Algorithm: parsed.Algorithm, StopOnError: parsed.StopOnError == "true"}
	for _, item := range parsed.Items {
		result.Items = append(result.Items, BatchItem{ID: item.ID, Format: item.Format,
			Suboperation: firstNonEmpty(item.Suboperation, "sign"), Reference: strings.TrimSpace(item.DataSource)})
	}
	return result, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// TriSign is one signature of triphase data: the server's pre-signature
// (PRE) and, after the client, its signature value (PK1) (E.3, E.4).
type TriSign struct {
	ID     string
	SignID string
	Params map[string]string
}

// TriphaseData is what the pre-signer answers and the post-signer receives.
type TriphaseData struct {
	Format string
	Signs  []TriSign
}

// PresignAnswer is the JSON pre-signer's answer: triphase data, and results
// for documents it could not prepare.
type PresignAnswer struct {
	Data    *TriphaseData
	Results []json.RawMessage
}

// ReadPresignJSON reads {"td": …, "results": […]}; td holds "signs":
// [{"signinfo": […]}] or "signinfo" directly.
func ReadPresignJSON(answer []byte) (PresignAnswer, error) {
	var parsed struct {
		TD *struct {
			Format   string         `json:"format"`
			SignInfo []jsonSignInfo `json:"signinfo"`
			Signs    []struct {
				SignInfo []jsonSignInfo `json:"signinfo"`
			} `json:"signs"`
		} `json:"td"`
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(answer, &parsed); err != nil {
		return PresignAnswer{}, Failure{Code: BatchSignature, Cause: "unreadable pre-sign answer"}
	}
	result := PresignAnswer{Results: parsed.Results}
	if parsed.TD == nil {
		return result, nil
	}
	data := &TriphaseData{Format: parsed.TD.Format}
	infos := parsed.TD.SignInfo
	for _, sign := range parsed.TD.Signs {
		infos = append(infos, sign.SignInfo...)
	}
	for _, info := range infos {
		params := map[string]string{}
		for key, value := range info.Params {
			params[key] = value
		}
		data.Signs = append(data.Signs, TriSign{ID: info.ID, SignID: info.SignID, Params: params})
	}
	result.Data = data
	return result, nil
}

type jsonSignInfo struct {
	ID     string            `json:"id"`
	SignID string            `json:"signid"`
	Params map[string]string `json:"params"`
}

// TriphaseJSON writes the tridata the JSON post-signer receives.
func (t TriphaseData) TriphaseJSON() []byte {
	infos := make([]jsonSignInfo, 0, len(t.Signs))
	for _, sign := range t.Signs {
		infos = append(infos, jsonSignInfo{ID: sign.ID, SignID: sign.SignID, Params: sign.Params})
	}
	encoded, _ := json.Marshal(struct {
		Format   string         `json:"format"`
		SignInfo []jsonSignInfo `json:"signinfo"`
	}{Format: t.Format, SignInfo: infos})
	return encoded
}

// xmlTriphase is the XML triphase data (E.3).
type xmlTriphase struct {
	XMLName xml.Name `xml:"xml"`
	Firmas  struct {
		Format string `xml:"format,attr"`
		Firma  []struct {
			ID     string `xml:"Id,attr"`
			SignID string `xml:"signid,attr"`
			Params []struct {
				Name  string `xml:"n,attr"`
				Value string `xml:",chardata"`
			} `xml:"param"`
		} `xml:"firma"`
	} `xml:"firmas"`
}

// ReadTriphaseXML reads the XML pre-signer's answer.
func ReadTriphaseXML(answer []byte) (TriphaseData, error) {
	var parsed xmlTriphase
	if err := xml.Unmarshal(answer, &parsed); err != nil {
		return TriphaseData{}, Failure{Code: BatchSignature, Cause: "unreadable pre-sign answer"}
	}
	data := TriphaseData{Format: parsed.Firmas.Format}
	for _, firma := range parsed.Firmas.Firma {
		params := map[string]string{}
		for _, param := range firma.Params {
			params[param.Name] = strings.TrimSpace(param.Value)
		}
		data.Signs = append(data.Signs, TriSign{ID: firma.ID, SignID: firma.SignID, Params: params})
	}
	return data, nil
}

// TriphaseXML writes the tridata the XML post-signer receives.
func (t TriphaseData) TriphaseXML() []byte {
	var builder strings.Builder
	builder.WriteString(`<xml><firmas format="`)
	xml.EscapeText(&builder, []byte(t.Format))
	builder.WriteString(`">`)
	for _, sign := range t.Signs {
		builder.WriteString(`<firma Id="`)
		xml.EscapeText(&builder, []byte(sign.ID))
		builder.WriteString(`" signid="`)
		xml.EscapeText(&builder, []byte(sign.SignID))
		builder.WriteString(`">`)
		for key, value := range sign.Params {
			builder.WriteString(`<param n="`)
			xml.EscapeText(&builder, []byte(key))
			builder.WriteString(`">`)
			xml.EscapeText(&builder, []byte(value))
			builder.WriteString(`</param>`)
		}
		builder.WriteString(`</firma>`)
	}
	builder.WriteString(`</firmas></xml>`)
	return []byte(builder.String())
}

// WithResults is the JSON batch the post-signer receives when the pre-signer
// reported results: each failed item keeps its id and carries the result and
// description instead of its data (E.3).
func WithResults(definition []byte, results []json.RawMessage) ([]byte, error) {
	if len(results) == 0 {
		return definition, nil
	}
	var batch map[string]any
	if err := json.Unmarshal(definition, &batch); err != nil {
		return nil, Failure{Code: Params, Cause: "unreadable JSON batch"}
	}
	outcomes := map[string]map[string]any{}
	for _, raw := range results {
		var result map[string]any
		if json.Unmarshal(raw, &result) == nil {
			if id, ok := result["id"].(string); ok {
				outcomes[id] = result
			}
		}
	}
	items, _ := batch["singlesigns"].([]any)
	for _, entry := range items {
		item, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		id, _ := item["id"].(string)
		outcome, failed := outcomes[id]
		if !failed {
			continue
		}
		for _, key := range []string{"datareference", "format", "suboperation", "extraparams"} {
			delete(item, key)
		}
		item["result"], item["description"] = outcome["result"], outcome["description"]
	}
	return json.Marshal(batch)
}

// EarlyResult is the answer when the pre-signer prepared nothing:
// {"signs": results}.
func EarlyResult(results []json.RawMessage) []byte {
	if results == nil {
		results = []json.RawMessage{}
	}
	encoded, _ := json.Marshal(map[string]any{"signs": results})
	return encoded
}
