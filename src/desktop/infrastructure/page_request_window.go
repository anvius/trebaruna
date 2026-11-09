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

	details     *fyne.Container
	keySource   *widget.RadioGroup
	fileRow     *fileRow
	passphrase  *widget.Entry
	fileSource  *fyne.Container
	cards       *cardSource
	cardList    *application.ListCards
	storeList   *application.ListCards
	keyBox      *fyne.Container
	documentRow *fileRow
	saveRow     *fileRow
	status      *widget.Label
	approve     *widget.Button
	decline     *widget.Button
	closing     *widget.Button
	finished    bool
	cancel      context.CancelFunc
}

// RunPageRequest opens the approval window for a URI and blocks until it closes.
func RunPageRequest(options Options, uri string) {
	fyneApp := app.NewWithID("org.codeberg.simplicer.trebaruna")
	fyneApp.Settings().SetTheme(NewAppTheme(DefaultPalette()))
	fyneApp.SetIcon(fyne.NewStaticResource("trebaruna.png", appIconPNG))
	catalogue := messaging.For(options.Language)
	window := fyneApp.NewWindow(catalogue.PageTitle)
	window.Resize(fyne.NewSize(640, 720))

	request := newPageRequest(window, catalogue,
		application.NewReviewPageRequest(CommandLinePageRequests{BinaryPath: options.BinaryPath}),
		application.NewListCards(CommandLineCardReader{BinaryPath: options.BinaryPath}),
		application.NewListCards(CommandLineCardReader{BinaryPath: options.BinaryPath, Store: domain.StoreFirefox}))
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

	// Closing the window before deciding declines: the page hears CANCEL.
	window.SetCloseIntercept(func() {
		if !request.finished && request.session != nil {
			request.declined()
			return
		}
		window.Close()
	})
	return request
}

func (r *pageRequest) object() fyne.CanvasObject {
	body := container.NewVBox(r.details, r.keyBox, r.documentRow.object(), r.saveRow.object(), r.status)
	actions := container.NewHBox(r.decline, r.closing, layout.NewSpacer(), r.approve)
	return container.NewBorder(nil, container.NewPadded(actions), nil, nil, container.NewVScroll(container.NewPadded(body)))
}

// start opens the session and shows the first step.
func (r *pageRequest) start(uri string) {
	r.say(r.m.CertificateReading, widget.LowImportance)
	ctx, cancel := context.WithTimeout(context.Background(), pageRequestTimeout)
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
	case step.Outcome != nil:
		r.finish(*step.Outcome)
	case step.Proposal != nil:
		r.present(*step.Proposal)
	}
}

// present renders a proposal, or asks again after a refused certificate.
func (r *pageRequest) present(proposal domain.PageProposal) {
	first := r.proposal.Operation == ""
	r.proposal = proposal
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

	r.keyBox.Hidden = !proposal.NeedsKey()
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

// warningText translates the command's warnings, which are stable English.
func (r *pageRequest) warningText(warning string, proposal domain.PageProposal) string {
	switch {
	case strings.Contains(warning, "single DES"):
		return r.m.PageWarnDES
	case strings.Contains(warning, "will be downloaded from"):
		return fmt.Sprintf(r.m.PageWarnDownload, proposal.DataURL)
	case strings.Contains(warning, "documents stay on the site"):
		return r.m.PageWarnBatch
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
		r.cards.switchTo(r.cardList, r.m.NoCards, r.m.PINPlaceholder)
	case r.m.KeyFromFirefox:
		r.fileSource.Hide()
		r.cards.object().Show()
		r.cards.switchTo(r.storeList, r.m.NoFirefoxCertificates, r.m.FirefoxPasswordPlaceholder)
	}
}

// decision builds what the person chose.
func (r *pageRequest) decision() domain.PageDecision {
	decision := domain.PageDecision{Approved: true, Document: r.document, SaveTo: r.saveTo}
	if r.keySource.Selected == r.m.KeyFromFile {
		decision.KeyFile = domain.CertificateFile{Path: r.keyFile, Passphrase: r.passphrase.Text}
	} else {
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
	switch {
	case outcome.Declined():
		r.say(r.m.PageDeclined, widget.MediumImportance)
	case outcome.Succeeded():
		r.say(fmt.Sprintf(r.m.PageDone, r.proposal.Site), widget.SuccessImportance)
	case outcome.Error != "":
		r.say(fmt.Sprintf(r.m.PageFailed, outcome.Error), widget.DangerImportance)
	default:
		r.say(fmt.Sprintf(r.m.PageFailed, outcome.Answer), widget.DangerImportance)
	}
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
