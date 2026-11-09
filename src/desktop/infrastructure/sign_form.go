//go:build gui

package infrastructure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"

	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
)

// Preference keys. The certificate path, the timestamp authority and its
// account name are remembered because people sign with the same card through
// the same TSA for years; passphrases and passwords never are.
const (
	preferenceCertificate = "certificate.path"
	preferenceKeySource   = "certificate.source"
	preferenceTimestamp   = "timestamp.url"
	preferenceTSAUser     = "timestamp.user"
	preferenceLevel       = "signature.level"
)

// signForm is the left half of the signing tab: three steps and one button.
//
// Nothing the certificate or the document already says is asked for. The
// holder, identifier, issuer and expiry come from the certificate; the format
// from the document type; the page and position from where the seal sits on
// the page. What is left to type is the passphrase.
type signForm struct {
	window      fyne.Window
	m           messaging.Catalogue
	palette     Palette
	preferences fyne.Preferences
	signing     *application.SignFromDesktop
	inspect     *application.InspectCertificate
	cards       *cardSource
	// cardList and storeList feed the card source: the cards in the
	// readers, or the Firefox store.
	cardList  *application.ListCards
	storeList *application.ListCards
	pages     *pagePane
	// onCheck hands a signed file to the verification tab.
	onCheck func(path string)
	// onNetwork receives the connections a signature reported.
	onNetwork func([]transparency.Connection)

	document string
	// batch holds the documents of a batch; empty when one document is signed.
	batch []string
	// fingerprint is the SHA-256 shown for the document; the receipt must
	// report the same one, or the file changed between choosing and signing.
	fingerprint string
	certificate string
	format      domain.SignatureFormat
	summary     *domain.CertificateSummary
	reading     int
	debounce    *time.Timer
	// run starts background work; pause is the wait after typing (zero: read
	// at once).
	run   background
	pause time.Duration

	documentRow    *fileRow
	keySource      *widget.RadioGroup
	fileSource     *fyne.Container
	certificateRow *fileRow
	passphrase     *widget.Entry
	holder         *widget.Label
	holderDetails  *widget.Label
	standing       *widget.Label
	formatChoice   *widget.RadioGroup
	formatNote     *widget.Label
	sealNote       *widget.Label
	invisible      *widget.Check
	level          *widget.Select
	timestamp      *widget.Entry
	tsaUser        *widget.Entry
	tsaPassword    *widget.Entry
	timestampBox   *fyne.Container
	reason         *widget.Entry
	location       *widget.Entry
	status         *widget.Label
	signButton     *widget.Button
	afterSign      *fyne.Container
	signedPath     string
}

// newSignForm builds the form and restores the remembered certificate.
func newSignForm(
	window fyne.Window,
	m messaging.Catalogue,
	palette Palette,
	preferences fyne.Preferences,
	signing *application.SignFromDesktop,
	inspect *application.InspectCertificate,
	cards *application.ListCards,
	firefox *application.ListCards,
	pages *pagePane,
) *signForm {
	form := &signForm{
		window: window, m: m, palette: palette, preferences: preferences,
		signing: signing, inspect: inspect, pages: pages,
		format: domain.FormatPAdES,
		run:    offThread, pause: typingPause,
		cardList: cards, storeList: firefox,
	}

	form.documentRow = newFileRow(m.ChooseDocument, m.ChangeButton, m.DropHint, form.pickDocument)
	form.certificateRow = newFileRow(m.ChooseCertificate, m.ChangeButton, m.CertificateHint, form.pickCertificate)

	form.passphrase = widget.NewPasswordEntry()
	form.passphrase.SetPlaceHolder(m.PassphrasePlaceholder)
	form.passphrase.OnChanged = func(string) { form.readCertificateSoon() }
	form.passphrase.OnSubmitted = func(string) { form.readCertificate() }
	form.fileSource = container.NewVBox(form.certificateRow.object(), form.passphrase)

	// A card is offered next to the file, not in a menu: the Spanish DNIe and
	// the Italian signature cards are how most people hold their certificate.
	form.cards = newCardSource(m, cards, preferences, form.cardChosen, form.noCertificate)
	form.cards.object().Hide()
	form.keySource = widget.NewRadioGroup([]string{m.KeyFromFile, m.KeyFromCard, m.KeyFromFirefox},
		func(string) { form.keySourceChanged() })
	form.keySource.Horizontal = true
	form.keySource.Required = true

	form.holder = widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	form.holder.Wrapping = fyne.TextWrapWord
	form.holderDetails = caption("")
	form.standing = widget.NewLabel("")
	form.standing.Wrapping = fyne.TextWrapWord

	form.formatChoice = widget.NewRadioGroup(nil, func(label string) { form.chooseFormat(label) })
	form.formatChoice.Required = true
	form.formatNote = caption("")
	form.sealNote = caption("")

	form.invisible = widget.NewCheck(m.InvisibleSignature, func(bool) { form.formatChanged() })
	form.level = widget.NewSelect(form.levelLabels(), func(string) { form.levelChanged() })
	form.timestamp = widget.NewEntry()
	form.timestamp.SetPlaceHolder("https://")
	form.timestamp.SetText(preferences.String(preferenceTimestamp))
	form.tsaUser = widget.NewEntry()
	form.tsaUser.SetText(preferences.String(preferenceTSAUser))
	form.tsaPassword = widget.NewPasswordEntry()
	// Aruba's and InfoCert's authorities answer 401 without an account, which
	// is why the account sits next to the address instead of in a dialog.
	form.timestampBox = container.NewVBox(
		fieldLabel(m.TSALabel), form.timestamp, caption(m.LevelHint),
		fieldLabel(m.TSAUserLabel), form.tsaUser,
		fieldLabel(m.TSAPasswordLabel), form.tsaPassword,
		caption(m.TSAAccountHint),
	)
	form.level.SetSelected(form.labelFor(domain.SignatureLevel(preferences.StringWithFallback(preferenceLevel, string(domain.LevelBasic)))))

	form.reason = widget.NewEntry()
	form.location = widget.NewEntry()
	form.location.SetPlaceHolder(m.LocationPlaceholder)

	form.status = widget.NewLabel("")
	form.status.Wrapping = fyne.TextWrapWord
	form.signButton = widget.NewButtonWithIcon(m.SignButton, theme.ConfirmIcon(), form.sign)
	form.signButton.Importance = widget.HighImportance
	form.afterSign = container.NewGridWithColumns(3,
		widget.NewButtonWithIcon(m.OpenSigned, theme.FileIcon(), func() { openWithSystemViewer(form.signedPath) }),
		widget.NewButtonWithIcon(m.ShowFolder, theme.FolderIcon(), func() { openWithSystemViewer(filepath.Dir(form.signedPath)) }),
		widget.NewButtonWithIcon(m.CheckSignature, theme.SearchIcon(), func() {
			if form.onCheck != nil {
				form.onCheck(form.signedPath)
			}
		}),
	)
	form.afterSign.Hide()

	switch preferences.String(preferenceKeySource) {
	case "card":
		form.keySource.SetSelected(m.KeyFromCard)
		return form
	case domain.StoreFirefox:
		form.keySource.SetSelected(m.KeyFromFirefox)
		return form
	}
	form.keySource.SetSelected(m.KeyFromFile)
	if remembered := preferences.String(preferenceCertificate); remembered != "" && fileExists(remembered) {
		form.setCertificate(remembered)
	}
	return form
}

// object lays the form out: the steps scroll, the button stays in reach.
func (f *signForm) object() fyne.CanvasObject {
	m := f.m

	card := container.New(layout.NewCustomPaddedVBoxLayout(0), f.holder, f.holderDetails, f.standing)
	steps := container.NewVBox(
		f.step(1, m.StepDocument),
		f.documentRow.object(),
		f.step(2, m.StepCertificate),
		f.keySource,
		f.fileSource,
		f.cards.object(),
		card,
		f.step(3, m.StepSignature),
		f.formatChoice,
		f.formatNote,
		f.sealNote,
		widget.NewAccordion(widget.NewAccordionItem(m.MoreOptions, container.NewVBox(
			f.invisible,
			fieldLabel(m.LevelLabel), f.level,
			f.timestampBox,
			fieldLabel(m.ReasonLabel), f.reason,
			fieldLabel(m.LocationLabel), f.location,
		))),
	)

	action := container.NewVBox(widget.NewSeparator(), f.status, f.afterSign, f.signButton)
	return container.NewBorder(nil, container.NewPadded(action), nil, nil,
		container.NewVScroll(container.NewPadded(steps)))
}

// step renders a numbered heading. The numbers are real: the three steps are
// done in this order, and the button is the fourth.
func (f *signForm) step(number int, title string) fyne.CanvasObject {
	figure := canvas.NewText(fmt.Sprintf("%d", number), f.palette.Accent)
	figure.TextSize = 16
	figure.TextStyle = fyne.TextStyle{Bold: true}
	heading := canvas.NewText(title, f.palette.Text)
	heading.TextSize = 16
	heading.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewVBox(widget.NewSeparator(), container.NewHBox(figure, heading))
}

// fieldLabel is the caption above an input.
func fieldLabel(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	label.SizeName = theme.SizeNameCaptionText
	return label
}

// ---- document ----

func (f *signForm) pickDocument() {
	newFileOpen(f.window, nil, f.setDocument).Show()
}

// setDocument adopts a document: its type decides the formats on offer.
func (f *signForm) setDocument(path string) {
	f.batch = nil
	f.document = path
	f.fingerprint = ""
	f.run(func() { f.measure(path) })
	f.signedPath = ""
	f.afterSign.Hide()
	f.status.SetText("")

	formats := domain.FormatsFor(path)
	f.format = formats[0]
	labels := make([]string, 0, len(formats))
	for _, format := range formats {
		labels = append(labels, f.formatLabel(format))
	}
	f.formatChoice.Options = labels
	f.formatChoice.SetSelected(labels[0])
	if len(formats) == 1 {
		f.formatChoice.Hide()
		f.formatNote.SetText(f.m.FormatOnlyCAdES)
		f.formatNote.Show()
	} else {
		f.formatChoice.Show()
		f.formatNote.Hide()
	}
	f.formatChanged()
}

func (f *signForm) chooseFormat(label string) {
	if len(f.batch) > 0 {
		for _, format := range domain.BatchFormats() {
			if f.formatLabel(format) == label {
				f.format = format
				f.batchChanged()
			}
		}
		return
	}
	for _, format := range domain.FormatsFor(f.document) {
		if f.formatLabel(format) == label && format != f.format {
			f.format = format
			f.formatChanged()
		}
	}
}

// formatChanged updates what depends on the format: where the file will be
// written and whether there is a page to put a seal on.
func (f *signForm) formatChanged() {
	if f.document == "" {
		return
	}
	f.documentRow.show(f.document, f.documentNote())

	switch {
	case f.format.HasVisibleSeal() && f.invisible.Checked:
		f.pages.empty(f.m.InvisibleExplained)
		f.sealNote.SetText(f.m.InvisibleExplained)
		f.sealNote.Show()
	case f.format.HasVisibleSeal():
		f.pages.show(f.document)
		f.sealNote.SetText(f.m.SealOnPagePane)
		f.sealNote.Show()
	default:
		f.pages.withoutVisibleSeal()
		f.sealNote.Hide()
	}
	if f.format.HasVisibleSeal() {
		f.invisible.Enable()
	} else {
		f.invisible.Disable()
	}
}

// documentNote says where the result goes and, once measured, what exactly
// is about to be signed.
func (f *signForm) documentNote() string {
	output := domain.SigningIntent{DocumentPath: f.document, Format: f.format}.OutputName()
	note := fmt.Sprintf(f.m.DocumentSavedAs, filepath.Base(output))
	if f.fingerprint != "" {
		note += "\n" + fmt.Sprintf(f.m.DocumentFingerprint, f.fingerprint)
	}
	return note
}

// measure computes the document's SHA-256 off the UI thread.
func (f *signForm) measure(path string) {
	digest, err := fileFingerprint(path)
	if err != nil {
		return
	}
	fyne.Do(func() {
		if f.document != path {
			return
		}
		f.fingerprint = digest
		f.documentRow.show(f.document, f.documentNote())
	})
}

func (f *signForm) formatLabel(format domain.SignatureFormat) string {
	switch format {
	case domain.FormatCAdES:
		if strings.HasSuffix(strings.ToLower(f.document), ".p7m") {
			return f.m.FormatWrapLabel
		}
		return f.m.FormatCAdESLabel
	case domain.FormatXAdES:
		return f.m.FormatXAdESLabel
	case domain.FormatODF:
		return f.m.FormatODFLabel
	case domain.FormatOOXML:
		return f.m.FormatOOXMLLabel
	case domain.FormatCAdESDetached:
		return f.m.FormatDetachedLabel
	case domain.FormatCosign:
		return f.m.FormatCosignLabel
	case domain.FormatCountersign:
		return f.m.FormatCountersignLabel
	case domain.FormatEach:
		return f.m.FormatEachLabel
	}
	return f.m.FormatPAdESLabel
}

// ---- certificate ----

func (f *signForm) pickCertificate() {
	newFileOpen(f.window, []string{".p12", ".pfx", ".pem"}, func(path string) {
		f.setCertificate(path)
		f.window.Canvas().Focus(f.passphrase)
	}).Show()
}

// setCertificate adopts a certificate file and reads it right away: a PEM or
// an unprotected P12 needs no passphrase.
func (f *signForm) setCertificate(path string) {
	if f.keySource.Selected != f.m.KeyFromFile {
		f.keySource.SetSelected(f.m.KeyFromFile)
	}
	f.certificate = path
	f.certificateRow.show(path, "")
	f.preferences.SetString(preferenceCertificate, path)
	f.readCertificate()
}

// readCertificateSoon waits for the user to stop typing: reading on every
// keystroke would start a process per letter of the passphrase.
func (f *signForm) readCertificateSoon() {
	if f.debounce != nil {
		f.debounce.Stop()
	}
	if f.pause == 0 {
		f.readCertificate()
		return
	}
	f.debounce = time.AfterFunc(f.pause, func() { fyne.Do(f.readCertificate) })
}

// readCertificate fills the certificate card from the certificate itself.
func (f *signForm) readCertificate() {
	if f.certificate == "" || f.usesCard() {
		return
	}
	f.reading++
	ticket := f.reading
	file := domain.CertificateFile{Path: f.certificate, Passphrase: f.passphrase.Text}
	f.showStanding(f.m.CertificateReading, widget.LowImportance)

	f.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		summary, err := f.inspect.Execute(ctx, file)
		fyne.Do(func() {
			if ticket != f.reading {
				return
			}
			if err != nil {
				f.certificateFailed(err, file.Passphrase == "")
				return
			}
			f.certificateRead(summary)
		})
	})
}

func (f *signForm) certificateFailed(err error, withoutPassphrase bool) {
	f.clearCertificate()

	if problem, ok := err.(domain.Problem); ok && problem.Code == domain.ProblemLockedCertificate {
		// An empty passphrase on a protected file is the normal first state,
		// not a mistake: it gets an instruction, not an alarm.
		if withoutPassphrase {
			f.showStanding(f.m.CertificateNeedsPassphrase, widget.MediumImportance)
			return
		}
		f.showStanding(f.m.CertificateLocked, widget.DangerImportance)
		return
	}
	f.showStanding(translate(err, f.m), widget.DangerImportance)
}

func (f *signForm) certificateRead(summary domain.CertificateSummary) {
	now := time.Now()

	f.holder.SetText(summary.Holder)
	details := []string{}
	if summary.Identifier != "" {
		details = append(details, summary.Identifier)
	}
	if summary.Issuer != "" {
		details = append(details, fmt.Sprintf(f.m.IssuedBy, summary.Issuer))
	}
	details = append(details, fmt.Sprintf(f.m.ValidUntil, summary.NotAfter.Local().Format("02/01/2006")))
	f.holderDetails.SetText(strings.Join(details, "\n"))

	switch summary.Standing(now) {
	case domain.StandingExpired:
		f.showStanding(fmt.Sprintf(f.m.StandingExpired, summary.NotAfter.Local().Format("02/01/2006")), widget.DangerImportance)
	case domain.StandingQualified:
		f.showStanding(f.m.StandingQualified, widget.SuccessImportance)
	case domain.StandingTrusted:
		f.showStanding(f.m.StandingTrusted, widget.SuccessImportance)
	default:
		f.showStanding(f.m.StandingUntrusted, widget.WarningImportance)
	}
	if summary.ExpiresSoon(now) {
		f.showStanding(f.standing.Text+"\n"+fmt.Sprintf(f.m.CertificateExpiresSoon, summary.DaysLeft(now)), widget.WarningImportance)
	}

	f.pages.setIdentity(SealIdentity{Name: summary.Holder, Identifier: summary.Identifier})
	if strings.TrimSpace(f.location.Text) == "" && summary.Locality != "" {
		f.location.SetText(summary.Locality)
	}
	// Last, so a summary on record means the whole card has been filled.
	f.summary = &summary
}

// clearCertificate empties the certificate card and the seal's identity.
func (f *signForm) clearCertificate() {
	f.summary = nil
	f.holder.SetText("")
	f.holderDetails.SetText("")
	f.pages.setIdentity(SealIdentity{})
}

// noCertificate says why no certificate is chosen, in the verdict line.
func (f *signForm) noCertificate(text string, importance widget.Importance) {
	f.clearCertificate()
	f.showStanding(text, importance)
}

// usesCard reports whether the key comes from a card or the Firefox store,
// both listed and opened the same way.
func (f *signForm) usesCard() bool {
	return f.keySource.Selected == f.m.KeyFromCard || f.keySource.Selected == f.m.KeyFromFirefox
}

// keySourceChanged swaps the file and the card halves of the step. A pending
// file read is dropped: its answer would describe a certificate no longer in
// use.
func (f *signForm) keySourceChanged() {
	f.reading++
	f.clearCertificate()
	f.showStanding("", widget.LowImportance)
	switch f.keySource.Selected {
	case f.m.KeyFromCard:
		f.showListedSource("card", f.cardList, f.m.NoCards, f.m.PINPlaceholder)
		return
	case f.m.KeyFromFirefox:
		f.showListedSource(domain.StoreFirefox, f.storeList, f.m.NoFirefoxCertificates, f.m.FirefoxPasswordPlaceholder)
		return
	}
	f.preferences.SetString(preferenceKeySource, "file")
	f.cards.object().Hide()
	f.fileSource.Show()
	f.readCertificate()
}

// showListedSource replaces the file half with the list of a card or store,
// remembering which source was chosen.
func (f *signForm) showListedSource(remembered string, list *application.ListCards, empty, pinName string) {
	f.preferences.SetString(preferenceKeySource, remembered)
	f.fileSource.Hide()
	f.cards.object().Show()
	f.cards.switchTo(list, empty, pinName)
}

// cardToken is the label of the card chosen in the step, for card
// management; empty when no card is chosen, which means the only one present.
func (f *signForm) cardToken() string {
	if f.keySource.Selected != f.m.KeyFromCard || f.cards.chosen == nil {
		return ""
	}
	return f.cards.chosen.Token
}

// cardsChanged reads the cards again after their PIN changed, so the state
// shown is the card's new one.
func (f *signForm) cardsChanged() {
	if f.keySource.Selected == f.m.KeyFromCard {
		f.cards.refresh()
	}
}

// cardChosen fills the certificate card from the card's certificate: the
// listing already carries the holder and the issuer's standing.
func (f *signForm) cardChosen(certificate domain.CardCertificate) {
	f.certificateRead(certificate.Summary)
}

// keyIntent puts the key the step describes into the intent.
func (f *signForm) keyIntent(intent *domain.SigningIntent) {
	if f.usesCard() {
		intent.Card = f.cards.key()
		return
	}
	intent.Key = domain.CertificateFile{Path: f.certificate, Passphrase: f.passphrase.Text}
}

// cardRefused reacts to a PIN the card did not take: the PIN is cleared and
// the cards read again, so the attempts left show before the next try.
func (f *signForm) cardRefused(err error) {
	if problem, ok := err.(domain.Problem); ok && problem.StopsCard() && f.usesCard() {
		f.cards.refused()
	}
}

// showStanding sets the verdict line under the certificate.
func (f *signForm) showStanding(text string, importance widget.Importance) {
	f.standing.Importance = importance
	f.standing.SetText(text)
}

// ---- level ----

func (f *signForm) levelLabels() []string {
	labels := make([]string, 0, len(domain.Levels()))
	for _, level := range domain.Levels() {
		labels = append(labels, f.labelFor(level))
	}
	return labels
}

func (f *signForm) labelFor(level domain.SignatureLevel) string {
	switch level {
	case domain.LevelTimestamp:
		return f.m.LevelTimestampLabel
	case domain.LevelLongTerm:
		return f.m.LevelLongTermLabel
	case domain.LevelArchive:
		return f.m.LevelArchiveLabel
	}
	return f.m.LevelBasicLabel
}

func (f *signForm) selectedLevel() domain.SignatureLevel {
	for _, level := range domain.Levels() {
		if f.labelFor(level) == f.level.Selected {
			return level
		}
	}
	return domain.LevelBasic
}

// levelChanged shows the authority field only when the level uses one.
func (f *signForm) levelChanged() {
	if f.timestampBox == nil {
		return
	}
	if f.selectedLevel().NeedsTimestamp() {
		f.timestampBox.Show()
		return
	}
	f.timestampBox.Hide()
}

// ---- batch ----

// setDocuments adopts several documents at once; one is a normal document.
func (f *signForm) setDocuments(paths []string) {
	if len(paths) == 1 {
		f.setDocument(paths[0])
		return
	}
	f.batch = append([]string{}, paths...)
	f.document = paths[0]
	f.fingerprint = ""
	f.signedPath = ""
	f.afterSign.Hide()
	f.status.SetText("")

	f.format = domain.FormatEach
	labels := make([]string, 0, 3)
	for _, format := range domain.BatchFormats() {
		labels = append(labels, f.formatLabel(format))
	}
	f.formatChoice.Options = labels
	f.formatChoice.SetSelected(labels[0])
	f.formatChoice.Show()
	f.formatNote.Hide()
	f.batchChanged()
}

// batchChanged lists the documents and says where the seals go.
func (f *signForm) batchChanged() {
	names := make([]string, 0, len(f.batch))
	for _, path := range f.batch {
		names = append(names, filepath.Base(path))
	}
	f.documentRow.showMany(fmt.Sprintf(f.m.BatchTitle, len(f.batch)), strings.Join(names, "\n"))
	message := f.m.BatchSeal
	if f.invisible.Checked {
		message = f.m.InvisibleExplained
	}
	f.pages.empty(message)
	f.sealNote.SetText(message)
	f.sealNote.Show()
	f.invisible.Enable()
}

// signBatch signs every document with the same settings, one after another,
// and reports each one.
func (f *signForm) signBatch(base domain.SigningIntent) {
	documents := append([]string{}, f.batch...)
	format := f.format
	f.signButton.Disable()
	f.afterSign.Hide()

	f.run(func() {
		var failures []string
		var signed []domain.Receipt
		var refusal error
		for index, document := range documents {
			if refusal != nil {
				// The card refused the PIN: the next document would spend another
				// of its few attempts with the same PIN.
				failures = append(failures, filepath.Base(document)+": "+f.m.BatchNotTried)
				continue
			}
			fyne.Do(func() { f.report(fmt.Sprintf(f.m.BatchProgress, index+1, len(documents)), widget.LowImportance) })
			intent := base
			intent.DocumentPath = document
			intent.Format = format.For(document)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			receipt, err := f.signing.Execute(ctx, intent)
			cancel()
			if err != nil {
				failures = append(failures, filepath.Base(document)+": "+translate(err, f.m))
				if problem, ok := err.(domain.Problem); ok && problem.StopsCard() {
					refusal = err
				}
				continue
			}
			signed = append(signed, receipt)
		}

		fyne.Do(func() {
			f.signButton.Enable()
			var network []transparency.Connection
			for _, receipt := range signed {
				network = append(network, receipt.Network...)
			}
			if f.onNetwork != nil && len(network) > 0 {
				f.onNetwork(network)
			}
			message := fmt.Sprintf(f.m.BatchDone, len(signed), len(documents))
			importance := widget.SuccessImportance
			if len(failures) > 0 {
				message += "\n" + strings.Join(failures, "\n")
				importance = widget.WarningImportance
			}
			if summary := summarise(network, f.m); summary != "" {
				message += "\n" + summary
			}
			if len(signed) > 0 {
				f.signedPath = signed[0].SignedPath
				f.afterSign.Show()
			}
			f.report(message, importance)
			if refusal != nil {
				f.cardRefused(refusal)
			}
		})
	})
}

// ---- signing ----

// sign validates, signs off the UI thread, and reports in place.
func (f *signForm) sign() {

	intent := domain.SigningIntent{
		DocumentPath:      f.document,
		Format:            f.format,
		Level:             f.selectedLevel(),
		Seal:              domain.SealChoice{Page: 1},
		TimestampURL:      strings.TrimSpace(f.timestamp.Text),
		TimestampUser:     strings.TrimSpace(f.tsaUser.Text),
		TimestampPassword: f.tsaPassword.Text,
		Reason:            strings.TrimSpace(f.reason.Text),
		Location:          strings.TrimSpace(f.location.Text),
	}
	f.keyIntent(&intent)
	switch {
	case f.format.HasVisibleSeal() && f.invisible.Checked:
		intent.Invisible = true
	case f.format.HasVisibleSeal():
		intent.Seal = f.pages.choice()
	}
	if len(f.batch) > 0 {
		intent.Seal = domain.SealChoice{Page: 1}
		intent.Invisible = f.invisible.Checked
		intent.Format = f.format.For(f.batch[0])
		if err := intent.Validate(); err != nil {
			f.report(translate(err, f.m), widget.DangerImportance)
			return
		}
		f.signBatch(intent)
		return
	}
	if err := intent.Validate(); err != nil {
		f.report(translate(err, f.m), widget.DangerImportance)
		return
	}

	f.signButton.Disable()
	f.afterSign.Hide()
	f.report(f.m.SigningMessage, widget.LowImportance)

	f.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		receipt, err := f.signing.Execute(ctx, intent)

		fyne.Do(func() {
			f.signButton.Enable()
			if err != nil {
				f.report(translate(err, f.m), widget.DangerImportance)
				f.cardRefused(err)
				return
			}
			f.preferences.SetString(preferenceLevel, string(intent.Level))
			if intent.TimestampURL != "" {
				f.preferences.SetString(preferenceTimestamp, intent.TimestampURL)
				f.preferences.SetString(preferenceTSAUser, intent.TimestampUser)
			}
			f.signedPath = receipt.SignedPath
			message := fmt.Sprintf(f.m.SignedAs, filepath.Base(receipt.SignedPath))
			importance := widget.SuccessImportance
			if f.fingerprint != "" && receipt.DocumentDigest != "" && receipt.DocumentDigest != f.fingerprint {
				message += "\n" + fmt.Sprintf(f.m.DocumentChanged, receipt.DocumentDigest)
				importance = widget.WarningImportance
			}
			if summary := summarise(receipt.Network, f.m); summary != "" {
				message += "\n" + summary
			}
			if f.onNetwork != nil {
				f.onNetwork(receipt.Network)
			}
			f.report(message, importance)
			f.afterSign.Show()
		})
	})
}

func (f *signForm) report(text string, importance widget.Importance) {
	f.status.Importance = importance
	f.status.SetText(text)
}

// fileExists reports whether a regular file exists at path.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// fileFingerprint is the SHA-256 of a file in lower-case hex, read in chunks.
func fileFingerprint(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
