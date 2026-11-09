package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
)

// AnswerPage is the use case behind every afirma:// request: AutoFirma's
// behaviour, with one difference that is the point of trebaruna — nothing is
// signed, downloaded or sent before a person has seen it and said yes
// (ADR-0004), and the protocol's weaknesses are said, not hidden.
type AnswerPage struct {
	approver     Approver
	signer       PageSigner
	certificates CertificateReader
	fetcher      DataFetcher
	files        FileWriter
	courier      Courier
}

// NewAnswerPage wires the use case.
func NewAnswerPage(approver Approver, signer PageSigner, certificates CertificateReader,
	fetcher DataFetcher, files FileWriter, courier Courier) *AnswerPage {
	return &AnswerPage{approver: approver, signer: signer, certificates: certificates,
		fetcher: fetcher, files: files, courier: courier}
}

// Execute answers one request and returns the answer it delivered (or would
// deliver, when the page waits on no channel).
func (u *AnswerPage) Execute(ctx context.Context, invocation domain.Invocation) (domain.Answer, error) {
	switch invocation.Operation {
	case domain.Sign, domain.Cosign, domain.Countersign, domain.SignAndSave:
		request, err := domain.ReadSignRequest(invocation, true)
		if err != nil {
			return u.fail(ctx, channelOf(invocation), err)
		}
		return u.sign(ctx, request)
	case domain.SelectCert:
		common, err := domain.ReadCommon(invocation, true)
		if err != nil {
			return u.fail(ctx, channelOf(invocation), err)
		}
		return u.selectCertificate(ctx, common)
	case domain.Save:
		common, err := domain.ReadCommon(invocation, true)
		if err != nil {
			return u.fail(ctx, channelOf(invocation), err)
		}
		payload, err := domain.ResolvePayload(invocation.Param("dat"), invocation.Param("gzip") == "true")
		if err != nil || payload.Absent() {
			return u.fail(ctx, common.Channel, domain.Failure{Code: domain.Params, Cause: "save needs data"})
		}
		return u.save(ctx, common, payload, invocation.Param("filename"))
	case domain.WebSocket, domain.Service:
		// The local channels are TLS on 127.0.0.1 and need a certificate the
		// browser trusts; trebaruna installs no root for it (ADR-0013).
		return domain.Answer{}, domain.Failure{Code: domain.CannotOpenSocket,
			Cause: "the local channels need a trusted certificate that trebaruna does not install"}
	case domain.Load:
		// load has no intermediate-server return path in AutoFirma 1.9.
		return u.fail(ctx, channelOf(invocation), domain.Failure{Code: domain.UnsupportedOperation})
	}
	return u.fail(ctx, channelOf(invocation), domain.Failure{Code: domain.UnsupportedOperation})
}

// sign handles sign, cosign, countersign and signandsave.
func (u *AnswerPage) sign(ctx context.Context, request domain.SignRequest) (domain.Answer, error) {
	stop := u.waiting(request.Channel)
	defer stop()

	proposal := u.proposal(request.Operation, request.Common, request.Format.Name, request.Data)
	proposal.SuggestedName = request.FileName
	if request.Format.Triphase {
		return u.fail(ctx, request.Channel, domain.Failure{Code: domain.UnsupportedFormat, Cause: request.Format.Name + " (signed through the site's server) is not supported yet"})
	}
	decision, err := u.approver.Approve(ctx, proposal)
	if err != nil {
		return u.fail(ctx, request.Channel, domain.Failure{Code: domain.CannotAccessKeystore, Cause: err.Error()})
	}
	if !decision.Approved {
		return u.cancel(ctx, request.Channel)
	}

	data, chosen, err := u.data(ctx, request.Data, decision)
	if err != nil {
		return u.fail(ctx, request.Channel, err)
	}
	signed, err := u.signer.Sign(ctx, PageSignature{
		Crypto: request.Crypto, Format: request.Format, Algorithm: request.Algorithm,
		Properties: request.Properties, Data: data, Key: decision.Key,
	})
	if err != nil {
		var failure domain.Failure
		if !errors.As(err, &failure) {
			failure = domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
		}
		return u.fail(ctx, request.Channel, failure)
	}
	if request.Operation == domain.SignAndSave && decision.SavePath != "" {
		if err := u.files.Write(decision.SavePath, signed.Signature); err != nil {
			return u.fail(ctx, request.Channel, domain.Failure{Code: domain.CannotSaveData, Cause: err.Error()})
		}
	}
	return u.deliver(ctx, request.Channel, domain.SignAnswer(signed.Certificate, signed.Signature, chosen, request.Version))
}

// selectCertificate answers with the certificate the person chose.
func (u *AnswerPage) selectCertificate(ctx context.Context, common domain.Common) (domain.Answer, error) {
	stop := u.waiting(common.Channel)
	defer stop()

	decision, err := u.approver.Approve(ctx, u.proposal(domain.SelectCert, common, "", domain.Payload{}))
	if err != nil {
		return u.fail(ctx, common.Channel, domain.Failure{Code: domain.CannotAccessKeystore, Cause: err.Error()})
	}
	if !decision.Approved {
		return u.cancel(ctx, common.Channel)
	}
	certificate, err := u.certificates.Certificate(decision.Key)
	if err != nil {
		return u.fail(ctx, common.Channel, domain.Failure{Code: domain.CannotAccessKeystore, Cause: err.Error()})
	}
	return u.deliver(ctx, common.Channel, domain.CertificateAnswer(certificate))
}

// save writes the page's data where the person chose.
func (u *AnswerPage) save(ctx context.Context, common domain.Common, payload domain.Payload, name string) (domain.Answer, error) {
	stop := u.waiting(common.Channel)
	defer stop()

	proposal := u.proposal(domain.Save, common, "", payload)
	proposal.ChooseFile, proposal.SuggestedName = false, name
	decision, err := u.approver.Approve(ctx, proposal)
	if err != nil || !decision.Approved || decision.SavePath == "" {
		return u.cancel(ctx, common.Channel)
	}
	data, _, err := u.data(ctx, payload, decision)
	if err != nil {
		return u.fail(ctx, common.Channel, err)
	}
	if err := u.files.Write(decision.SavePath, data); err != nil {
		return u.fail(ctx, common.Channel, domain.Failure{Code: domain.CannotSaveData, Cause: err.Error()})
	}
	return u.deliver(ctx, common.Channel, domain.SavedAnswer())
}

// proposal describes the request for the person.
func (u *AnswerPage) proposal(operation domain.Operation, common domain.Common, format string, payload domain.Payload) Proposal {
	proposal := Proposal{
		Operation: operation, Site: common.Site(), AppName: common.AppName, Format: format,
		DataURL: payload.URL, ChooseFile: payload.Absent(), Filter: domain.FilterFrom(common.Properties),
	}
	if len(payload.Bytes) > 0 {
		sum := sha256.Sum256(payload.Bytes)
		proposal.DataSize, proposal.DataSHA256 = len(payload.Bytes), hex.EncodeToString(sum[:])
	}
	if common.Channel.Ciphered() && common.Channel.Cipher == "" {
		proposal.Warnings = append(proposal.Warnings,
			"the answer travels to the site encrypted with single DES and an 8-digit key: anyone who sees it can read it")
	}
	if payload.URL != "" {
		proposal.Warnings = append(proposal.Warnings, "the data will be downloaded from "+payload.URL+" once you approve")
	}
	if unsupported := proposal.Filter.Unsupported; len(unsupported) > 0 {
		proposal.Warnings = append(proposal.Warnings, fmt.Sprintf("certificate filter conditions not understood, so no certificate matches them: %v", unsupported))
	}
	return proposal
}

// data returns the bytes to sign or save: the page's, the downloaded ones,
// or the file the person chose.
func (u *AnswerPage) data(ctx context.Context, payload domain.Payload, decision Decision) ([]byte, string, error) {
	switch {
	case len(payload.Bytes) > 0:
		return payload.Bytes, "", nil
	case payload.URL != "":
		fetched, err := u.fetcher.Fetch(ctx, payload.URL)
		if err != nil {
			return nil, "", domain.Failure{Code: domain.CannotReadData, Cause: err.Error()}
		}
		return fetched, "", nil
	case len(decision.File) > 0:
		return decision.File, decision.FileName, nil
	}
	return nil, "", domain.Failure{Code: domain.CannotReadData}
}

// waiting keeps the page waiting while the person decides, when it asked.
func (u *AnswerPage) waiting(channel domain.Channel) func() {
	if !channel.ActiveWaiting || channel.StorageURL == "" || channel.SessionID == "" {
		return func() {}
	}
	return u.courier.Wait(channel)
}

// deliver sends a successful answer.
func (u *AnswerPage) deliver(ctx context.Context, channel domain.Channel, answer domain.Answer) (domain.Answer, error) {
	if channel.StorageURL == "" || channel.SessionID == "" {
		return answer, nil
	}
	if err := u.courier.Deliver(ctx, channel, answer); err != nil {
		return answer, domain.Failure{Code: domain.SendingResult, Cause: err.Error()}
	}
	return answer, nil
}

// cancel delivers CANCEL.
func (u *AnswerPage) cancel(ctx context.Context, channel domain.Channel) (domain.Answer, error) {
	return u.deliver(ctx, channel, domain.Answer{Elements: []string{domain.CancelAnswer}, Plain: true})
}

// fail delivers a failure and returns it.
func (u *AnswerPage) fail(ctx context.Context, channel domain.Channel, err error) (domain.Answer, error) {
	var failure domain.Failure
	if !errors.As(err, &failure) {
		failure = domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	answer := domain.Answer{Elements: []string{failure.Answer()}, Plain: true, Failure: true}
	if _, deliverErr := u.deliver(ctx, channel, answer); deliverErr != nil {
		return answer, deliverErr
	}
	return answer, failure
}

// channelOf reads the channel of a request that failed validation, so the
// page still hears why: only fields that passed their own checks are used.
func channelOf(invocation domain.Invocation) domain.Channel {
	channel := domain.Channel{Key: invocation.Param("key"), SessionID: invocation.Param("id")}
	if len(channel.Key) != 8 {
		channel.Key = ""
	}
	if storage := invocation.Param("stservlet"); domain.ValidServletURL(storage) == nil {
		channel.StorageURL = storage
	}
	return channel
}
