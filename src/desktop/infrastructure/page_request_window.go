//go:build gui

package infrastructure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

// pageRequest is the window an afirma:// URI opens: the request in full, the
// certificate to answer with, and two buttons. Nothing is signed or sent
// before the person presses the one that says so (ADR-0004).
type pageRequest struct {
	m       messaging.Catalogue
	window  fyne.Window
	review  *application.ReviewPageRequest
	session application.PageSession
	run     background

	proposal domain.PageProposal
	document string
	saveTo   string
	keyFile  string

	details    *fyne.Container
	keySource  *widget.RadioGroup
	fileRow    *fileRow
	passphrase *widget.Entry
	fileSource *fyne.Container
	cards      *cardSource
	cardList   *application.ListCards
	storeList  *application.ListCards
	keyBox     *fyne.Container
	// remembered offers the certificate kept from the page's earlier
	// request (sticky) instead of choosing one; rememberedBox holds it with
	// the holder's name, which wraps.
	remembered    *widget.Check
	rememberedFor *widget.Label
	rememberedBox *fyne.Container
	documentRow   *fileRow
	saveRow       *fileRow
	status        *widget.Label
	approve       *widget.Button
	decline       *widget.Button
	closing       *widget.Button
	finished      bool
	cancel        context.CancelFunc

	// uri is the request, started again once the local certificate is
	// installed; localChannel installs it; installLocal offers to.
	uri          string
	localChannel *application.ManageLocalChannel
	installLocal *widget.Button
	// deciding is true while a proposal waits for the person.
	deciding bool
}

// RunPageRequest opens the approval window for a URI and blocks until it closes.
func RunPageRequest(options Options, uri string) {
	fyneApp := app.NewWithID("org.codeberg.simplicer.trebaruna")
	useTheme(fyneApp)
	fyneApp.SetIcon(fyne.NewStaticResource("trebaruna.png", appIconPNG))
	catalogue := messaging.For(options.Language)
	window := fyneApp.NewWindow(catalogue.PageTitle)
	window.Resize(fyne.NewSize(640, 720))

	request := newPageRequest(window, catalogue,
		application.NewReviewPageRequest(CommandLinePageRequests{BinaryPath: options.BinaryPath}),
		application.NewListCards(CommandLineCardReader{BinaryPath: options.BinaryPath}),
		application.NewListCards(CommandLineCardReader{BinaryPath: options.BinaryPath, Store: domain.StoreFirefox}))
	request.localChannel = application.NewManageLocalChannel(CommandLineLocalChannel{BinaryPath: options.BinaryPath})
	window.SetContent(request.object())
	request.start(uri)
	window.ShowAndRun()
}

func newPageRequest(window fyne.Window, m messaging.Catalogue, review *application.ReviewPageRequest,
	cards, firefox *application.ListCards) *pageRequest {
	request := &pageRequest{m: m, window: window, review: review, run: offThread, cardList: cards, storeList: firefox}

	request.details = container.NewVBox()
	request.fileRow = newFileRow(m.ChooseCertificate, m.ChangeButton, m.CertificateHint, request.pickKey)
	request.passphrase = widget.NewPasswordEntry()
	request.passphrase.SetPlaceHolder(m.PassphrasePlaceholder)
	request.fileSource = container.NewVBox(request.fileRow.object(), request.passphrase)
	request.cards = newCardSource(m, cards, fyne.CurrentApp().Preferences(),
		func(domain.CardCertificate) { request.say(request.rejection(), widget.DangerImportance) },
		func(text string, importance widget.Importance) { request.say(text, importance) })
	request.cards.object().Hide()
	request.keySource = widget.NewRadioGroup([]string{m.KeyFromFile, m.KeyFromCard, m.KeyFromFirefox}, func(string) { request.keySourceChanged() })
	request.keySource.Horizontal = true
	request.keyBox = container.NewVBox(fieldLabel(m.PageKeyTitle), request.keySource, request.fileSource, request.cards.object())
	request.remembered = widget.NewCheck(m.PageUseRemembered, func(bool) { request.rememberedChanged() })
	request.rememberedFor = wrapped("", widget.LowImportance)
	request.rememberedBox = container.NewVBox(request.remembered, request.rememberedFor)
	request.rememberedBox.Hide()
	request.documentRow = newFileRow(m.PageDocument, m.ChangeButton, m.PageChooseFile, request.pickDocument)
	request.saveRow = newFileRow(m.PageSaveTo, m.ChangeButton, "", request.pickSaveTo)
	request.status = widget.NewLabel("")
	request.status.Wrapping = fyne.TextWrapWord
	request.approve = widget.NewButtonWithIcon(m.PageApprove, theme.ConfirmIcon(), request.approved)
	request.approve.Importance = widget.HighImportance
	request.decline = widget.NewButtonWithIcon(m.PageDecline, theme.CancelIcon(), request.declined)
	request.closing = widget.NewButton(m.PageClose, window.Close)
	request.closing.Hide()
	request.approve.Disable()
	request.installLocal = widget.NewButtonWithIcon(m.PageInstallLocalTLS, theme.ConfirmIcon(), request.installLocalChannel)
	request.installLocal.Importance = widget.HighImportance
	request.installLocal.Hide()

	// Closing the window before deciding declines: the page hears CANCEL.
	// Between the requests of a local channel, it ends the channel.
	window.SetCloseIntercept(func() {
		switch {
		case !request.finished && request.session != nil && request.deciding:
			request.declined()
			return
		case !request.finished && request.cancel != nil:
			request.cancel()
		}
		window.Close()
	})
	return request
}

func (r *pageRequest) object() fyne.CanvasObject {
	body := container.NewVBox(r.details, r.rememberedBox, r.keyBox, r.documentRow.object(), r.saveRow.object(), r.status)
	actions := container.NewHBox(r.decline, r.closing, layout.NewSpacer(), r.approve, r.installLocal)
	return container.NewBorder(nil, container.NewPadded(actions), nil, nil, container.NewVScroll(container.NewPadded(body)))
}

// start opens the session and shows the first step.
func (r *pageRequest) start(uri string) {
	r.uri = uri
	r.say(r.m.CertificateReading, widget.LowImportance)
	timeout := pageRequestTimeout
	if strings.HasPrefix(uri, "afirma://websocket") {
		// A local channel lasts as long as the page's session.
		timeout = localChannelTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	r.cancel = cancel
	r.run(func() {
		session, err := r.review.Execute(ctx, uri)
		if err != nil {
			fyne.Do(func() { r.finish(domain.PageOutcome{Error: err.Error()}) })
			return
		}
		step, err := session.Next()
		fyne.Do(func() {
			r.session = session
			r.show(step, err)
		})
	})
}

// show presents a proposal or the outcome.
func (r *pageRequest) show(step domain.PageStep, err error) {
	switch {
	case err != nil:
		r.finish(domain.PageOutcome{Error: err.Error()})
	case step.Listening > 0:
		r.say(fmt.Sprintf(r.m.PageListening, step.Listening), widget.LowImportance)
		r.next()
	case step.Closed:
		r.finish(domain.PageOutcome{})
		r.say(r.m.PageSessionClosed, widget.MediumImportance)
	case step.Outcome != nil && step.Outcome.MissingLocalTLS:
		r.offerLocalChannel()
	case step.Outcome != nil && step.Outcome.Session:
		r.between(*step.Outcome)
	case step.Outcome != nil:
		r.finish(*step.Outcome)
	case step.Proposal != nil:
		r.present(*step.Proposal)
	}
}

// next shows the session's next step, read off the UI thread.
func (r *pageRequest) next() {
	session := r.session
	if session == nil {
		return
	}
	r.run(func() {
		step, err := session.Next()
		fyne.Do(func() { r.show(step, err) })
	})
}

// between says how one request of a local channel ended and waits for the
// page's next one, shown afresh.
func (r *pageRequest) between(outcome domain.PageOutcome) {
	text, importance := r.outcomeText(outcome)
	r.say(text+"\n"+r.m.PageNextRequest, importance)
	r.approve.Disable()
	r.decline.Disable()
	r.proposal = domain.PageProposal{}
	r.next()
}

// offerLocalChannel explains that the page needs the local certificate
// and offers to install it, then to start the request again.
func (r *pageRequest) offerLocalChannel() {
	r.approve.Hide()
	r.decline.Hide()
	r.closing.Show()
	r.say(r.m.PageLocalTLSMissing, widget.WarningImportance)
	if r.localChannel != nil {
		r.installLocal.Show()
		r.installLocal.Enable()
	}
}

// installLocalChannel installs the certificate and opens the channel again.
func (r *pageRequest) installLocalChannel() {
	r.installLocal.Disable()
	r.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, err := r.localChannel.Execute(ctx, "install")
		fyne.Do(func() {
			if err != nil {
				r.installLocal.Enable()
				r.say(fmt.Sprintf(r.m.PageFailed, err.Error()), widget.DangerImportance)
				return
			}
			r.installLocal.Hide()
			r.closing.Hide()
			r.approve.Show()
			r.decline.Show()
			r.start(r.uri)
		})
	})
}

// present renders a proposal, or asks again after a refused certificate.
func (r *pageRequest) present(proposal domain.PageProposal) {
	first := r.proposal.Operation == ""
	r.proposal = proposal
	r.deciding = true
	r.approve.Enable()
	r.decline.Enable()
	if proposal.Rejected != "" {
		r.say(fmt.Sprintf(r.m.PageRejected, proposal.Rejected), widget.DangerImportance)
		return
	}
	r.say("", widget.LowImportance)
	if !first {
		return
	}

	m := r.m
	title := widget.NewLabelWithStyle(m.PageTitle, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	lines := []fyne.CanvasObject{title, wrapped(r.operationText(proposal), widget.MediumImportance)}
	if proposal.Site != "" {
		lines = append(lines, wrapped(fmt.Sprintf(m.PageSite, proposal.Site), widget.MediumImportance))
	}
	if proposal.AppName != "" {
		lines = append(lines, caption(fmt.Sprintf(m.PageAppName, proposal.AppName)))
	}
	if proposal.Format != "" && proposal.Operation != "batch" {
		lines = append(lines, caption(fmt.Sprintf(m.PageFormat, proposal.Format)))
	}
	if proposal.Policy != "" {
		lines = append(lines, caption(fmt.Sprintf(m.PagePolicy, proposal.Policy)))
	}
	if len(proposal.Roles) > 0 {
		lines = append(lines, caption(fmt.Sprintf(m.PageRoles, strings.Join(proposal.Roles, ", "))))
	}
	if proposal.Place != "" {
		lines = append(lines, caption(fmt.Sprintf(m.PagePlace, proposal.Place)))
	}
	switch {
	case proposal.DataSize > 0:
		data := selectableCaption()
		data.SetText(fmt.Sprintf(m.PageData, proposal.DataSize, proposal.DataSHA256))
		lines = append(lines, data)
	case proposal.DataURL != "":
		lines = append(lines, wrapped(fmt.Sprintf(m.PageDataURL, proposal.DataURL), widget.WarningImportance))
	}
	for _, item := range proposal.Items {
		lines = append(lines, caption(fmt.Sprintf("%s (%s, %s)", item.ID, item.Format, item.Suboperation)))
	}
	if len(proposal.Filters) > 0 {
		lines = append(lines, caption(fmt.Sprintf(m.PageFilters, strings.Join(proposal.Filters, "; "))))
	}
	for _, warning := range proposal.Warnings {
		lines = append(lines, wrapped(r.warningText(warning, proposal), widget.WarningImportance))
	}
	r.details.Objects = lines
	r.details.Refresh()

	r.rememberedBox.Hide()
	if proposal.NeedsKey() && proposal.Remembered != "" {
		r.rememberedFor.SetText(fmt.Sprintf(m.PageRememberedHolder, proposal.Remembered))
		r.rememberedBox.Show()
		r.remembered.SetChecked(true)
	}
	r.rememberedChanged()
	r.documentRow.object().Hide()
	if proposal.ChooseFile {
		r.documentRow.object().Show()
	}
	r.saveRow.object().Hide()
	if proposal.Saves() {
		r.saveRow.object().Show()
	}
	switch proposal.Operation {
	case "selectcert":
		r.approve.SetText(m.PageApproveCertificate)
	case "save":
		r.approve.SetText(m.PageApproveSave)
	}
	if proposal.NeedsKey() && r.keySource.Selected == "" {
		r.keySource.SetSelected(m.KeyFromCard)
	}
}

// rejection repeats why the last certificate was refused, or says nothing.
func (r *pageRequest) rejection() string {
	if r.proposal.Rejected == "" {
		return ""
	}
	return fmt.Sprintf(r.m.PageRejected, r.proposal.Rejected)
}

// operationText names what the page asks.
func (r *pageRequest) operationText(proposal domain.PageProposal) string {
	switch proposal.Operation {
	case "cosign":
		return r.m.PageOpCosign
	case "countersign":
		return r.m.PageOpCountersign
	case "signandsave":
		return r.m.PageOpSignAndSave
	case "selectcert":
		return r.m.PageOpSelectCert
	case "save":
		return r.m.PageOpSave
	case "batch":
		if len(proposal.Items) == 1 {
			return r.m.PageOpBatchOne
		}
		return fmt.Sprintf(r.m.PageOpBatch, len(proposal.Items))
	}
	return r.m.PageOpSign
}

// referencedPrefix opens the command's list of documents an Externally
// Detached signature covers by address and digest.
const referencedPrefix = "the signature covers documents trebaruna does not see, by address and digest: "

// warningText translates the command's warnings, which are stable English.
func (r *pageRequest) warningText(warning string, proposal domain.PageProposal) string {
	switch {
	case strings.Contains(warning, "single DES"):
		return r.m.PageWarnDES
	case strings.Contains(warning, "will be downloaded from"):
		return fmt.Sprintf(r.m.PageWarnDownload, proposal.DataURL)
	case strings.Contains(warning, "documents stay on the site"):
		return r.m.PageWarnBatch
	case strings.Contains(warning, "prepared by the site's server "):
		host, _, _ := strings.Cut(strings.TrimPrefix(warning, "the signature is prepared by the site's server "), ":")
		return fmt.Sprintf(r.m.PageWarnTriphase, host)
	case strings.Contains(warning, "a bare signature (NONE)"):
		return r.m.PageWarnBare
	case strings.HasPrefix(warning, referencedPrefix):
		return fmt.Sprintf(r.m.PageWarnReferenced, strings.TrimPrefix(warning, referencedPrefix))
	case strings.HasPrefix(warning, "the page sends only the "):
		algorithm, rest, _ := strings.Cut(strings.TrimPrefix(warning, "the page sends only the "), " digest of a document, ")
		digest, _, _ := strings.Cut(rest, ", not the document")
		return fmt.Sprintf(r.m.PageWarnDigest, algorithm, digest)
	case strings.Contains(warning, "filter conditions not understood"):
		return r.m.PageWarnFilters
	}
	return warning
}

// keySourceChanged shows the file or the card half.
func (r *pageRequest) keySourceChanged() {
	switch r.keySource.Selected {
	case r.m.KeyFromFile:
		r.cards.object().Hide()
		r.fileSource.Show()
	case r.m.KeyFromCard:
		r.fileSource.Hide()
		r.cards.object().Show()
		r.cards.switchTo(r.cardList, r.m.NoCards, r.m.PINPlaceholder, r.m.SearchCards)
	case r.m.KeyFromFirefox:
		r.fileSource.Hide()
		r.cards.object().Show()
		r.cards.switchTo(r.storeList, r.m.NoFirefoxCertificates, r.m.FirefoxPasswordPlaceholder, r.m.SearchCards)
	}
}

// rememberedChanged hides the key choice while the kept certificate is
// used, and shows it when the person wants another.
func (r *pageRequest) rememberedChanged() {
	r.keyBox.Hidden = !r.proposal.NeedsKey() || r.usesRemembered()
	r.keyBox.Refresh()
}

// usesRemembered reports the kept certificate offered and accepted.
func (r *pageRequest) usesRemembered() bool { return r.rememberedBox.Visible() && r.remembered.Checked }

// decision builds what the person chose.
func (r *pageRequest) decision() domain.PageDecision {
	decision := domain.PageDecision{Approved: true, Document: r.document, SaveTo: r.saveTo}
	switch {
	case r.usesRemembered():
		decision.Remembered = true
	case r.keySource.Selected == r.m.KeyFromFile:
		decision.KeyFile = domain.CertificateFile{Path: r.keyFile, Passphrase: r.passphrase.Text}
	default:
		decision.Card = r.cards.key()
	}
	return decision
}

// approved sends the decision and waits for what follows.
func (r *pageRequest) approved() {
	decision := r.decision()
	if err := decision.Validate(r.proposal); err != nil {
		r.say(translate(err, r.m), widget.DangerImportance)
		return
	}
	r.send(decision)
}

// declined tells the page no.
func (r *pageRequest) declined() { r.send(domain.PageDecision{}) }

// send writes the decision off the UI thread and shows the next step.
func (r *pageRequest) send(decision domain.PageDecision) {
	if r.session == nil {
		return
	}
	r.approve.Disable()
	r.decline.Disable()
	r.deciding = false
	r.say(fmt.Sprintf(r.m.PageWorking, r.proposal.Site), widget.LowImportance)
	session := r.session
	r.run(func() {
		if err := session.Decide(decision); err != nil {
			fyne.Do(func() { r.finish(domain.PageOutcome{Error: err.Error()}) })
			return
		}
		step, err := session.Next()
		fyne.Do(func() { r.show(step, err) })
	})
}

// finish says how the request ended and leaves only Close.
func (r *pageRequest) finish(outcome domain.PageOutcome) {
	r.finished = true
	r.approve.Hide()
	r.decline.Hide()
	r.closing.Show()
	r.say(r.outcomeText(outcome))
	session, cancel := r.session, r.cancel
	r.run(func() {
		if session != nil {
			_ = session.Close()
		}
		if cancel != nil {
			cancel()
		}
	})
}

// outcomeText is how a request ended, in the person's words.
func (r *pageRequest) outcomeText(outcome domain.PageOutcome) (string, widget.Importance) {
	switch {
	case outcome.Declined():
		return r.m.PageDeclined, widget.MediumImportance
	case outcome.Succeeded():
		return fmt.Sprintf(r.m.PageDone, r.proposal.Site), widget.SuccessImportance
	case outcome.Error != "":
		return fmt.Sprintf(r.m.PageFailed, outcome.Error), widget.DangerImportance
	}
	return fmt.Sprintf(r.m.PageFailed, outcome.Answer), widget.DangerImportance
}

func (r *pageRequest) say(text string, importance widget.Importance) {
	r.status.Importance = importance
	r.status.SetText(text)
}

func (r *pageRequest) pickKey() {
	newFileOpen(r.window, []string{".p12", ".pfx", ".pem"}, func(path string) {
		r.keyFile = path
		r.fileRow.show(path, "")
		r.window.Canvas().Focus(r.passphrase)
	}).Show()
}

func (r *pageRequest) pickDocument() {
	newFileOpen(r.window, nil, func(path string) {
		r.document = path
		r.documentRow.show(path, "")
	}).Show()
}

func (r *pageRequest) pickSaveTo() {
	save := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		r.saveTo = writer.URI().Path()
		_ = writer.Close()
		r.saveRow.show(r.saveTo, "")
	}, r.window)
	if r.proposal.SuggestedName != "" {
		save.SetFileName(r.proposal.SuggestedName)
	}
	save.Show()
}

// wrapped is a wrapping label with an importance.
func wrapped(text string, importance widget.Importance) *widget.Label {
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	label.Importance = importance
	return label
}

// pageRequestTimeout bounds a whole request, the person's decision included.
const pageRequestTimeout = 15 * time.Minute

// localChannelTimeout bounds a local channel's whole session.
const localChannelTimeout = 4 * time.Hour
