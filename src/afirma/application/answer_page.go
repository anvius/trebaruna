package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
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
	requests     RequestStore
	batches      BatchServices
	raw          RawSigner
	// kept is the key a page asked to keep (sticky) for its next request
	// in this process, a WebSocket session's.
	kept *keptKey
}

// keptKey is a kept key and the holder its certificate names.
type keptKey struct {
	key    signing.Signer
	holder string
}

// WithBatches adds the batch services and the raw signer; without them a
// batch is answered as unsupported.
func (u *AnswerPage) WithBatches(services BatchServices, raw RawSigner) *AnswerPage {
	u.batches, u.raw = services, raw
	return u
}

// NewAnswerPage wires the use case.
func NewAnswerPage(approver Approver, signer PageSigner, certificates CertificateReader,
	fetcher DataFetcher, files FileWriter, courier Courier, requests RequestStore) *AnswerPage {
	return &AnswerPage{approver: approver, signer: signer, certificates: certificates,
		fetcher: fetcher, files: files, courier: courier, requests: requests}
}

// Execute answers one request and returns the answer it delivered (or would
// deliver, when the page waits on no channel).
func (u *AnswerPage) Execute(ctx context.Context, invocation domain.Invocation) (domain.Answer, error) {
	invocation, err := u.uploaded(ctx, invocation)
	if err != nil {
		return u.fail(ctx, channelOf(invocation), err)
	}
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
	case domain.Batch:
		request, err := domain.ReadBatchRequest(invocation, true)
		if err != nil {
			return u.fail(ctx, channelOf(invocation), err)
		}
		return u.batch(ctx, request)
	case domain.WebSocket, domain.Service:
		// A WebSocket channel is served around this use case, by
		// AnswerLocalChannel (ADR-0019), never from inside a request; the
		// legacy socket is not offered.
		return domain.Answer{}, domain.Failure{Code: domain.CannotOpenSocket,
			Cause: "a local channel is not opened from inside a request, and the legacy socket is not offered"}
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
	if wanted := domain.SealWanted(request.Properties); wanted != "" && signsPDF(request) {
		// The seal goes on the PDF the page sent, or on the one the person
		// chooses; a PDF fetched after the approval cannot have it placed.
		proposal.PlaceSeal = wanted
		switch {
		case bytes.HasPrefix(request.Data.Bytes, []byte("%PDF")):
			proposal.SealDocument = request.Data.Bytes
		case request.Data.URL != "":
			proposal.Warnings = append(proposal.Warnings, sealLaterWarning)
		}
	}
	switch algorithm := request.Properties["precalculatedHashAlgorithm"]; {
	case request.Format.Family == "xades" && domain.ExternallyDetached(request.Properties):
		// The documents are named by address and digest; an invalid list
		// is refused before the person is asked.
		documents, err := domain.References(request.Properties, request.Data.Bytes)
		if err != nil {
			return u.fail(ctx, request.Channel, err)
		}
		described := make([]string, len(documents))
		for index, document := range documents {
			described[index] = fmt.Sprintf("%s (%s %x)", document.URI, document.Algorithm, document.Digest)
		}
		proposal.Warnings = append(proposal.Warnings, referencedWarning+strings.Join(described, ", "))
	case algorithm != "" && len(request.Data.Bytes) > 0:
		proposal.Warnings = append(proposal.Warnings, fmt.Sprintf("the page sends only the %s digest of a document, %x, not the document: "+
			"trebaruna cannot show it; compare the digest with the document's if you have it", algorithm, request.Data.Bytes))
	}
	switch {
	case request.Format.Family == "none":
		// NONEtri's server prepares nothing, which triphaseSign checks.
		proposal.Warnings = append(proposal.Warnings, bareWarning)
	case request.Format.Triphase:
		// The signature is prepared and assembled by the site's server: the
		// person learns which one before approving.
		proposal.Warnings = append(proposal.Warnings,
			"the signature is prepared by the site's server "+serverHost(request.Properties["serverUrl"])+
				": you sign what that server computes, which trebaruna cannot show")
	}
	decision, err := u.approve(ctx, proposal)
	if err != nil {
		return u.fail(ctx, request.Channel, approvalFailure(err))
	}
	if !decision.Approved {
		return u.cancel(ctx, request.Channel)
	}

	data, chosen, err := u.data(ctx, request.Data, decision)
	if err != nil {
		return u.fail(ctx, request.Channel, err)
	}
	if request.Format.Triphase {
		certificate, id, err := u.triphaseSign(ctx, request, data, decision)
		if err != nil {
			return u.fail(ctx, request.Channel, err)
		}
		return u.deliver(ctx, request.Channel, domain.SignAnswer(certificate, id, chosen, request.Version))
	}
	properties := request.Properties
	if proposal.PlaceSeal != "" && !decision.Seal.IsZero() {
		properties = decision.Seal.Into(properties)
	}
	signed, err := u.signer.Sign(ctx, PageSignature{
		Crypto: request.Crypto, Format: request.Format, Algorithm: request.Algorithm,
		Properties: properties, Data: data, Key: decision.Key,
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

// sealLaterWarning is said when the page wants a visible seal on a PDF that
// arrives only after the approval: there is nothing to place it on yet.
const sealLaterWarning = "the page asks for a visible seal, but the document is fetched only after you approve: the signature will be invisible"

// signsPDF reports a PDF signature: PAdES, or auto over a PDF.
func signsPDF(request domain.SignRequest) bool {
	switch {
	case request.Crypto == domain.Countersign:
		return false
	case request.Format.Family == "pades":
		return true
	}
	return request.Format.Auto() && (bytes.HasPrefix(request.Data.Bytes, []byte("%PDF")) || len(request.Data.Bytes) == 0)
}

// referencedWarning opens the list of documents an Externally Detached
// signature covers by address and digest.
const referencedWarning = "the signature covers documents trebaruna does not see, by address and digest: "

// bareWarning is said of a NONE signature, which is the page's bytes signed
// as they are: nothing in it says what they are.
const bareWarning = "a bare signature (NONE) records nothing of what it signs: if these bytes are the signed part of another signature, " +
	"you sign whatever that one covers, which trebaruna cannot show"

// selectCertificate answers with the certificate the person chose.
func (u *AnswerPage) selectCertificate(ctx context.Context, common domain.Common) (domain.Answer, error) {
	stop := u.waiting(common.Channel)
	defer stop()

	decision, err := u.approve(ctx, u.proposal(domain.SelectCert, common, "", domain.Payload{}))
	if err != nil {
		return u.fail(ctx, common.Channel, approvalFailure(err))
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
	decision, err := u.approve(ctx, proposal)
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

// maximumChoices is how many times a person may pick a certificate the page
// does not accept before the request fails.
const maximumChoices = 3

// approve asks the person and holds the choice to the page's certificate
// filter, as AutoFirma offers only matching certificates: a certificate that
// does not match is refused with the reason, and the person may choose again.
func (u *AnswerPage) approve(ctx context.Context, proposal Proposal) (Decision, error) {
	for attempt := 0; attempt < maximumChoices; attempt++ {
		decision, err := u.approver.Approve(ctx, proposal)
		if err != nil || !decision.Approved || proposal.Operation == domain.Save {
			return decision, err
		}
		if decision.UseRemembered {
			if u.kept == nil || proposal.Remembered == "" {
				return Decision{}, domain.Failure{Code: domain.CannotAccessKeystore, Cause: "no key was kept for this page"}
			}
			decision.Key = u.kept.key
		}
		raw, err := u.certificates.Certificate(decision.Key)
		if err != nil {
			return Decision{}, err
		}
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return Decision{}, err
		}
		var neighbours []*x509.Certificate
		if proposal.Filter.Pairs() {
			if neighbours, err = u.neighbours(decision.Key); err != nil {
				return Decision{}, err
			}
		}
		if proposal.Filter.Accepts(certificate, neighbours, time.Now()) {
			if proposal.keep {
				u.kept = &keptKey{key: decision.Key, holder: certificate.Subject.CommonName}
			}
			return decision, nil
		}
		proposal.Rejected = certificate.Subject.CommonName + " is not a certificate this page accepts" +
			" (expired, or outside its filters)"
	}
	return Decision{}, domain.Failure{Code: domain.NoCertificatesKeystore}
}

// neighbours are the other certificates of the key's store; one that cannot
// be read pairs with nothing.
func (u *AnswerPage) neighbours(key signing.Signer) ([]*x509.Certificate, error) {
	raws, err := u.certificates.Neighbours(key)
	if err != nil {
		return nil, err
	}
	var neighbours []*x509.Certificate
	for _, raw := range raws {
		if certificate, err := x509.ParseCertificate(raw); err == nil {
			neighbours = append(neighbours, certificate)
		}
	}
	return neighbours, nil
}

// approvalFailure keeps a failure the approval step decided (SAF_19) and
// reports any other error as the keystore's (SAF_08).
func approvalFailure(err error) error {
	var failure domain.Failure
	if errors.As(err, &failure) {
		return failure
	}
	return domain.Failure{Code: domain.CannotAccessKeystore, Cause: err.Error()}
}

// proposal describes the request for the person.
func (u *AnswerPage) proposal(operation domain.Operation, common domain.Common, format string, payload domain.Payload) Proposal {
	proposal := Proposal{
		Operation: operation, Site: common.Site(), AppName: common.AppName, Format: format,
		DataURL: payload.URL, ChooseFile: payload.Absent(), Filter: domain.FilterFrom(common.Properties),
		Policy: domain.DeclaredPolicy(common.Properties), Roles: domain.ClaimedRoles(common.Properties),
		Place: domain.DeclaredPlace(common.Properties), keep: common.Sticky,
	}
	if common.ResetSticky {
		u.kept = nil
	}
	if common.Sticky && u.kept != nil {
		proposal.Remembered = u.kept.holder
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

// uploaded replaces a URI that only names an uploaded request (fileid and
// rtservlet, no data) with the request itself (C.1); the URI's key and
// cipher stay, since the page puts them only there.
func (u *AnswerPage) uploaded(ctx context.Context, invocation domain.Invocation) (domain.Invocation, error) {
	fileID, retrieve := invocation.Param("fileid"), invocation.Param("rtservlet")
	if fileID == "" || invocation.Param("dat") != "" {
		return invocation, nil
	}
	if retrieve == "" || u.requests == nil {
		return invocation, domain.Failure{Code: domain.Params, Cause: "fileid without rtservlet"}
	}
	if err := domain.ValidServletURL(retrieve); err != nil {
		return invocation, err
	}
	fetched, err := u.requests.Fetch(ctx, retrieve, fileID, invocation.Param("key"), invocation.Param("cipher"),
		invocation.Param("jsonbatch") == "true")
	if err != nil {
		return invocation, err
	}
	merged := map[string]string{}
	for _, name := range fetched.Names() {
		merged[name] = fetched.Param(name)
	}
	for _, name := range []string{"key", "cipher", "stservlet", "aw"} {
		if merged[name] == "" && invocation.Param(name) != "" {
			merged[name] = invocation.Param(name)
		}
	}
	return domain.InvocationOf(fetched.Operation, merged), nil
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

// serverHost names a server by its host, or as given when it is no URL.
func serverHost(address string) string {
	if parsed, err := url.Parse(address); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return address
}
