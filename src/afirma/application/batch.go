package application

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
)

// batch signs a batch: through the site's pre- and post-signers (the
// documents stay on the site and the key signs what its server prepares), or
// locally item by item (E.3–E.6).
func (u *AnswerPage) batch(ctx context.Context, request domain.BatchRequest) (domain.Answer, error) {
	if u.batches == nil || u.raw == nil {
		return u.fail(ctx, request.Channel, domain.Failure{Code: domain.UnsupportedOperation})
	}
	definition, err := domain.ReadBatchDefinition(request.Definition, request.JSON)
	if err != nil {
		return u.fail(ctx, request.Channel, err)
	}
	stop := u.waiting(request.Channel)
	defer stop()

	proposal := u.proposal(domain.Batch, request.Common, describeBatch(definition), domain.Payload{})
	proposal.ChooseFile, proposal.Items = false, definition.Items
	if !request.Local {
		proposal.Warnings = append(proposal.Warnings,
			"the documents stay on the site: you sign what its server prepares from them, which trebaruna cannot show")
	}
	decision, err := u.approve(ctx, proposal)
	if err != nil {
		return u.fail(ctx, request.Channel, approvalFailure(err))
	}
	if !decision.Approved {
		return u.cancel(ctx, request.Channel)
	}

	chain, err := u.raw.Chain(decision.Key)
	if err != nil || len(chain) == 0 {
		return u.fail(ctx, request.Channel, domain.Failure{Code: domain.CannotAccessKeystore, Cause: fmt.Sprint(err)})
	}
	var result []byte
	if request.Local {
		result = u.localBatch(ctx, definition, decision)
	} else {
		result, err = u.triphaseBatch(ctx, request, definition, decision, chain)
		if err != nil {
			return u.fail(ctx, request.Channel, err)
		}
	}
	return u.deliver(ctx, request.Channel, domain.BatchAnswer(result, chain[0], request.NeedCertificate))
}

// triphaseBatch runs pre-sign, the client's signatures and post-sign.
func (u *AnswerPage) triphaseBatch(ctx context.Context, request domain.BatchRequest, definition domain.BatchDefinition,
	decision Decision, chain [][]byte) ([]byte, error) {
	answer, err := u.batches.Presign(ctx, request.PresignURL, request.JSON, request.Definition, chain)
	if err != nil {
		return nil, serviceFailure(err)
	}
	batchForPost := request.Definition
	var data domain.TriphaseData
	if request.JSON {
		presign, err := domain.ReadPresignJSON(answer)
		if err != nil {
			return nil, err
		}
		if presign.Data == nil {
			return domain.EarlyResult(presign.Results), nil
		}
		data = *presign.Data
		if batchForPost, err = domain.WithResults(request.Definition, presign.Results); err != nil {
			return nil, err
		}
	} else {
		data, err = domain.ReadTriphaseXML(answer)
		if err != nil {
			return nil, err
		}
	}
	if len(data.Signs) == 0 {
		return nil, domain.Failure{Code: domain.BatchSignature, Cause: "the pre-signer prepared no signature"}
	}

	inputs := make([][]byte, len(data.Signs))
	for index, sign := range data.Signs {
		pre, err := base64.StdEncoding.DecodeString(sign.Params["PRE"])
		if err != nil || len(pre) == 0 {
			return nil, domain.Failure{Code: domain.BatchSignature, Cause: "a pre-signature is missing or unreadable"}
		}
		inputs[index] = pre
	}
	signatures, err := u.raw.SignAll(decision.Key, inputs, domain.DigestOf(definition.Algorithm))
	if err != nil {
		return nil, domain.Failure{Code: domain.BatchSignature, Cause: err.Error()}
	}
	for index, sign := range data.Signs {
		sign.Params["PK1"] = base64.StdEncoding.EncodeToString(signatures[index])
		if sign.Params["NEED_PRE"] != "true" {
			delete(sign.Params, "PRE")
		}
	}

	triphase := data.TriphaseXML()
	if request.JSON {
		triphase = data.TriphaseJSON()
	}
	result, err := u.batches.Postsign(ctx, request.PostsignURL, request.JSON, batchForPost, chain, triphase)
	if err != nil {
		return nil, serviceFailure(err)
	}
	return result, nil
}

// localBatch signs every item here (E.6): the reference is the data in
// Base64; with stoponerror, the items after a failure are skipped.
func (u *AnswerPage) localBatch(ctx context.Context, definition domain.BatchDefinition, decision Decision) []byte {
	type outcome struct {
		ID          string `json:"id"`
		Result      string `json:"result"`
		Description string `json:"description,omitempty"`
		Signature   string `json:"signature,omitempty"`
	}
	outcomes := make([]outcome, 0, len(definition.Items))
	stopped := false
	for _, item := range definition.Items {
		if stopped {
			outcomes = append(outcomes, outcome{ID: item.ID, Result: "SKIPPED"})
			continue
		}
		signature, err := u.signLocalItem(ctx, definition, item, decision)
		if err != nil {
			outcomes = append(outcomes, outcome{ID: item.ID, Result: "ERROR_PRE", Description: err.Error()})
			stopped = definition.StopOnError
			continue
		}
		outcomes = append(outcomes, outcome{ID: item.ID, Result: "DONE_AND_SAVED", Signature: base64.StdEncoding.EncodeToString(signature)})
	}
	encoded, _ := json.Marshal(map[string]any{"signs": outcomes})
	return encoded
}

// signLocalItem signs one item of a local batch.
func (u *AnswerPage) signLocalItem(ctx context.Context, definition domain.BatchDefinition, item domain.BatchItem, decision Decision) ([]byte, error) {
	data, err := domain.DecodeBase64(item.Reference)
	if err != nil || len(data) == 0 {
		return nil, errors.New("the item's data are not Base64")
	}
	format, err := domain.ParseFormat(firstOf(item.Format, definition.Format))
	if err != nil {
		return nil, err
	}
	properties := map[string]string{}
	if definition.ExtraParams != "" {
		if decoded, err := domain.DecodeBase64(definition.ExtraParams); err == nil {
			properties = domain.ParseProperties(strings.ReplaceAll(string(decoded), `\n`, "\n"))
		}
	}
	signed, err := u.signer.Sign(ctx, PageSignature{Crypto: domain.Operation(item.Suboperation), Format: format,
		Algorithm: definition.Algorithm, Properties: properties, Data: data, Key: decision.Key})
	if err != nil {
		return nil, err
	}
	return signed.Signature, nil
}

// describeBatch summarises a batch for the person.
func describeBatch(definition domain.BatchDefinition) string {
	return fmt.Sprintf("%d document(s), %s, %s", len(definition.Items), firstOf(definition.Format, "per document"), definition.Algorithm)
}

// serviceFailure maps a batch service's HTTP status to AutoFirma's code
// (E.7): 400 is a parameter error, other 4xx a communication error, the rest
// the service's own failure.
func serviceFailure(err error) error {
	var failure ServiceFailure
	if errors.As(err, &failure) {
		switch {
		case failure.Status == 400:
			return domain.Failure{Code: domain.Params, Cause: failure.Error()}
		case failure.Status >= 400 && failure.Status < 500:
			return domain.Failure{Code: domain.ContactBatchService, Cause: failure.Error()}
		}
	}
	return domain.Failure{Code: domain.BatchSignature, Cause: err.Error()}
}

func firstOf(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
