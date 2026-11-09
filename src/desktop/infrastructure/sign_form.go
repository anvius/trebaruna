//go:build gui

package infrastructure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	pdflib "github.com/digitorus/pdf"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"

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
	preferenceRubric      = "seal.rubric"
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
	// remoteList lists a remote service's credentials, reached as remote
	// says.
	remoteList *application.ListCards
	remote     *remoteAccount
	// formFields finds the boxes a PDF form reserves for signatures; fields
	// are the current document's.
	formFields *application.ListFormFields
	fields     []domain.FormField
	pages      *pagePane
	// onCheck hands a signed file to the verification tab.
	onCheck func(path string)
	// onNetwork receives the connections a signature reported.
	onNetwork func([]transparency.Connection)
	// onKeyChange hears that a certificate was read or cleared: the
	// envelopes window opens with the same key.
	onKeyChange func()

	document string
	// batch holds the documents of a batch; empty when one document is signed.
	batch []string
	// fingerprint is the SHA-256 shown for the document; the receipt must
	// report the same one, or the file changed between choosing and signing.
	fingerprint string
	certificate string
	format      domain.SignatureFormat
	// offered are the formats on offer for the document, as listed.
	offered  []domain.SignatureFormat
	summary  *domain.CertificateSummary
	reading  int
	debounce *time.Timer
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
	// pdfPasswordBox asks for the password of a PDF that opens only with
	// one.
	pdfPassword    *widget.Entry
	pdfPasswordBox *fyne.Container
	// invoiceBox asks a FacturaE invoice's role and policy version;
	// policyBox, under More options, the policy other signatures declare.
	invoiceBox    *fyne.Container
	invoiceRole   *widget.RadioGroup
	invoicePolicy *widget.Select
	policyBox     *fyne.Container
	policy        *widget.Select
	sealNote      *widget.Label
	fieldChoice   *widget.Select
	fieldBox      *fyne.Container
	// rubric is the handwritten signature the seal carries, from rubricPath.
	rubricPath   string
	rubricRow    *fileRow
	rubricRemove *widget.Button
	rubricBox    *fyne.Container
	invisible    *widget.Check
	level        *widget.Select
	timestamp    *widget.Entry
	tsaUser      *widget.Entry
	tsaPassword  *widget.Entry
	timestampBox *fyne.Container
	reason       *widget.Entry
	location     *widget.Entry
	status       *widget.Label
	signButton   *widget.Button
	afterSign    *fyne.Container
	signedPath   string
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
	remote *application.ListCards,
	account *remoteAccount,
	formFields *application.ListFormFields,
	pages *pagePane,
) *signForm {
	form := &signForm{
		window: window, m: m, palette: palette, preferences: preferences,
		signing: signing, inspect: inspect, pages: pages,
		format: domain.FormatPAdES,
		run:    offThread, pause: typingPause,
		cardList: cards, storeList: firefox, remoteList: remote, remote: account, formFields: formFields,
	}
	form.remote.object().Hide()

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
	form.keySource = widget.NewRadioGroup([]string{m.KeyFromFile, m.KeyFromCard, m.KeyFromFirefox, m.KeyFromRemote},
		func(string) { form.keySourceChanged() })
	// One under another: four sources side by side widened the form past
	// its share of the window, at the page's expense, in every language.
	form.keySource.Horizontal = false
	form.keySource.Required = true

	form.holder = widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	form.holder.Wrapping = fyne.TextWrapWord
	form.holderDetails = caption("")
	form.standing = widget.NewLabel("")
	form.standing.Wrapping = fyne.TextWrapWord

	form.formatChoice = widget.NewRadioGroup(nil, func(label string) { form.chooseFormat(label) })
	form.formatChoice.Required = true
	form.formatNote = caption("")
	form.pdfPassword = widget.NewPasswordEntry()
	form.pdfPasswordBox = container.NewVBox(fieldLabel(m.PDFPasswordLabel), form.pdfPassword, caption(m.PDFPasswordHint))
	form.pdfPasswordBox.Hide()
	form.invoiceRole = widget.NewRadioGroup([]string{m.InvoiceRoleIssuer, m.InvoiceRoleReceiver, m.InvoiceRoleThird}, nil)
	form.invoiceRole.Required = true
	form.invoiceRole.SetSelected(m.InvoiceRoleIssuer)
	form.invoicePolicy = widget.NewSelect([]string{m.PolicyFacturaELabel, m.PolicyFacturaE30Label}, nil)
	form.invoicePolicy.SetSelected(m.PolicyFacturaELabel)
	form.invoiceBox = container.NewVBox(caption(m.InvoiceDetected), fieldLabel(m.InvoiceRoleLabel), form.invoiceRole,
		fieldLabel(m.PolicyLabel), form.invoicePolicy)
	form.invoiceBox.Hide()
	form.policy = widget.NewSelect(nil, nil)
	form.policyBox = container.NewVBox(fieldLabel(m.PolicyLabel), form.policy, caption(m.PolicyHint))
	form.policyBox.Hide()
	form.sealNote = caption("")
	form.fieldChoice = widget.NewSelect(nil, func(string) { form.formatChanged() })
	form.fieldBox = container.NewVBox(fieldLabel(m.FormFieldLabel), form.fieldChoice, caption(m.FormFieldsOffered))
	form.fieldBox.Hide()

	form.rubricRow = newFileRow(m.ChooseRubric, m.ChangeButton, m.RubricHint, form.pickRubric)
	form.rubricRemove = widget.NewButtonWithIcon(m.RemoveRubric, theme.DeleteIcon(), form.removeRubric)
	form.rubricRemove.Hide()
	form.rubricBox = container.NewVBox(fieldLabel(m.RubricLabel), form.rubricRow.object(), form.rubricRemove)
	form.rubricBox.Hide()
	if remembered := preferences.String(preferenceRubric); remembered != "" && fileExists(remembered) {
		form.setRubric(remembered)
	}

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
	case domain.StoreRemote:
		form.keySource.SetSelected(m.KeyFromRemote)
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
		f.pdfPasswordBox,
		f.step(2, m.StepCertificate),
		f.keySource,
		f.fileSource,
		f.remote.object(),
		f.cards.object(),
		card,
		f.step(3, m.StepSignature),
		f.formatChoice,
		f.formatNote,
		f.invoiceBox,
		f.fieldBox,
		f.sealNote,
		f.rubricBox,
		widget.NewAccordion(widget.NewAccordionItem(m.MoreOptions, container.NewVBox(
			f.invisible,
			fieldLabel(m.LevelLabel), f.level,
			f.timestampBox,
			fieldLabel(m.ReasonLabel), f.reason,
			fieldLabel(m.LocationLabel), f.location,
			f.policyBox,
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
	f.offerFields(nil)
	f.run(func() { f.measure(path) })
	if domain.FormatsFor(path)[0].HasVisibleSeal() && f.formFields != nil {
		f.run(func() {
			fields := f.formFields.Execute(context.Background(), path)
			fyne.Do(func() {
				if f.document == path {
					f.offerFields(fields)
				}
			})
		})
	}
	f.signedPath = ""
	f.afterSign.Hide()
	f.status.SetText("")

	f.offerFormats(domain.FormatsFor(path))
	f.pdfPassword.SetText("")
	f.pdfPasswordBox.Hide()
	if strings.EqualFold(filepath.Ext(path), ".pdf") {
		// A PDF that opens only with a password asks for it; one that only
		// restricts permissions opens without.
		f.run(func() {
			locked := pdfNeedsPassword(path)
			fyne.Do(func() {
				if f.document == path && locked {
					f.pdfPasswordBox.Show()
				}
			})
		})
	}
	if strings.EqualFold(filepath.Ext(path), ".xml") {
		// A FacturaE invoice is signed as one: its root says so.
		f.run(func() {
			content, err := os.ReadFile(path)
			if err != nil || !signingdomain.IsFacturaEInvoice(content) {
				return
			}
			fyne.Do(func() {
				if f.document == path && len(f.batch) == 0 {
					f.offerFormats(domain.InvoiceFormats())
				}
			})
		})
	}
}

// offerFormats lists the formats on offer for the document, the first
// chosen.
func (f *signForm) offerFormats(formats []domain.SignatureFormat) {
	f.offered = formats
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
	for _, format := range f.offered {
		if f.formatLabel(format) == label && format != f.format {
			f.format = format
			f.formatChanged()
		}
	}
}

// offerFields lists the form's empty signature fields to sign in, after
// the choice to place the seal on the page; a document with none hides the
// choice.
func (f *signForm) offerFields(fields []domain.FormField) {
	f.fields = fields
	options := []string{f.m.FormFieldNone}
	for _, field := range fields {
		options = append(options, fmt.Sprintf(f.m.FormFieldOption, field.Name, field.Page))
	}
	f.fieldChoice.Options = options
	// Repopulating is not a choice: the seal is redrawn once, below.
	changed := f.fieldChoice.OnChanged
	f.fieldChoice.OnChanged = nil
	f.fieldChoice.SetSelectedIndex(0)
	f.fieldChoice.OnChanged = changed
	if len(fields) == 0 {
		f.fieldBox.Hide()
		return
	}
	f.formatChanged()
}

// chosenField is the form's field the person chose to sign in, if any.
func (f *signForm) chosenField() (domain.FormField, bool) {
	index := f.fieldChoice.SelectedIndex()
	if index < 1 || index > len(f.fields) || !f.format.HasVisibleSeal() || len(f.batch) > 0 {
		return domain.FormField{}, false
	}
	return f.fields[index-1], true
}

// formatChanged updates what depends on the format: where the file will be
// written and whether there is a page to put a seal on.
func (f *signForm) formatChanged() {
	if f.document == "" {
		return
	}
	f.documentRow.show(f.document, f.documentNote())
	f.policiesChanged()

	f.rubricBox.Hide()
	f.fieldBox.Hide()
	if f.format.HasVisibleSeal() && len(f.fields) > 0 {
		f.fieldBox.Show()
	}
	field, inField := f.chosenField()
	switch {
	case f.format.HasVisibleSeal() && f.invisible.Checked:
		f.pages.empty(f.m.InvisibleExplained)
		f.sealNote.SetText(f.m.InvisibleExplained)
		f.sealNote.Show()
	case inField:
		f.pages.showField(f.document, field)
		f.sealNote.SetText(f.m.FormFieldSealHint)
		f.sealNote.Show()
		f.rubricBox.Show()
	case f.format.HasVisibleSeal():
		f.pages.show(f.document)
		f.sealNote.SetText(f.m.SealOnPagePane)
		f.sealNote.Show()
		f.rubricBox.Show()
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
	if len(f.batch) == 0 && fileExists(output) {
		// The window shows the name before signing, so it replaces the file
		// the person was told about (the command is given --force).
		note += "\n" + f.m.DocumentReplaces
	}
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
	case domain.FormatASiCS:
		return f.m.FormatASiCSLabel
	case domain.FormatASiCE:
		return f.m.FormatASiCELabel
	case domain.FormatFacturaE:
		return f.m.FormatFacturaELabel
	}
	return f.m.FormatPAdESLabel
}

// policyLabel names a policy in the person's language.
func (f *signForm) policyLabel(policy domain.PolicyName) string {
	switch policy {
	case domain.PolicyAGE:
		return f.m.PolicyAGELabel
	case domain.PolicyAGE18:
		return f.m.PolicyAGE18Label
	case domain.PolicyFacturaE:
		return f.m.PolicyFacturaELabel
	case domain.PolicyFacturaE30:
		return f.m.PolicyFacturaE30Label
	}
	return f.m.PolicyNoneLabel
}

// policiesChanged offers the policies the format can declare: an invoice's
// in its own box, the others under More options, keeping the one chosen
// when it still fits.
func (f *signForm) policiesChanged() {
	f.invoiceBox.Hide()
	f.policyBox.Hide()
	if f.format == domain.FormatFacturaE {
		f.invoiceBox.Show()
		return
	}
	policies := f.format.Policies()
	if len(policies) == 0 {
		return
	}
	labels := make([]string, len(policies))
	for index, policy := range policies {
		labels[index] = f.policyLabel(policy)
	}
	chosen := f.policy.Selected
	f.policy.Options = labels
	if !slices.Contains(labels, chosen) {
		chosen = labels[0]
	}
	f.policy.SetSelected(chosen)
	f.policyBox.Show()
}

// chosenPolicy and chosenRole are what the signature declares.
func (f *signForm) chosenPolicy() domain.PolicyName {
	selected := f.policy.Selected
	if f.format == domain.FormatFacturaE {
		selected = f.invoicePolicy.Selected
	}
	for _, policy := range f.format.Policies() {
		if f.policyLabel(policy) == selected {
			return policy
		}
	}
	return domain.PolicyNone
}

func (f *signForm) chosenRole() string {
	if f.format != domain.FormatFacturaE {
		return ""
	}
	labels := []string{f.m.InvoiceRoleIssuer, f.m.InvoiceRoleReceiver, f.m.InvoiceRoleThird}
	for index, label := range labels {
		if label == f.invoiceRole.Selected {
			return domain.InvoiceRoles()[index]
		}
	}
	return ""
}

// ---- rubric ----

func (f *signForm) pickRubric() {
	newFileOpen(f.window, []string{".png", ".jpg", ".jpeg"}, f.setRubric).Show()
}

// setRubric adopts the image of a handwritten signature, refusing one that
// cannot be a rubric before anything is signed, and shows it in the seal.
func (f *signForm) setRubric(path string) {
	rubric, picture, err := readRubric(path)
	if err != nil {
		f.report(f.m.RubricInvalid, widget.DangerImportance)
		return
	}
	f.rubricPath = path
	f.rubricRow.show(path, "")
	f.rubricRemove.Show()
	f.preferences.SetString(preferenceRubric, path)
	f.pages.setRubric(rubric, picture)
}

// removeRubric takes the rubric out of the seal.
func (f *signForm) removeRubric() {
	f.rubricPath = ""
	f.rubricRow.clear()
	f.rubricRemove.Hide()
	f.preferences.SetString(preferenceRubric, "")
	f.pages.setRubric(signingdomain.Rubric{}, nil)
}

// readRubric reads a rubric and its picture for the preview.
func readRubric(path string) (signingdomain.Rubric, image.Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return signingdomain.Rubric{}, nil, err
	}
	defer file.Close()
	rubric, err := signingdomain.ReadRubric(file)
	if err != nil {
		return signingdomain.Rubric{}, nil, err
	}
	picture, _, err := image.Decode(bytes.NewReader(rubric.Content()))
	return rubric, picture, err
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
	f.keyChanged()
}

// clearCertificate empties the certificate card and the seal's identity.
func (f *signForm) clearCertificate() {
	f.summary = nil
	f.holder.SetText("")
	f.holderDetails.SetText("")
	f.pages.setIdentity(SealIdentity{})
	f.keyChanged()
}

func (f *signForm) keyChanged() {
	if f.onKeyChange != nil {
		f.onKeyChange()
	}
}

// chosenKey is the key the step describes, to open an envelope with, and
// its holder's name; ok is false while no certificate is read.
func (f *signForm) chosenKey() (domain.OpeningIntent, string, bool) {
	if f.summary == nil {
		return domain.OpeningIntent{}, "", false
	}
	var intent domain.SigningIntent
	f.keyIntent(&intent)
	return domain.OpeningIntent{Key: intent.Key, Card: intent.Card}, f.summary.Holder, true
}

// noCertificate says why no certificate is chosen, in the verdict line.
func (f *signForm) noCertificate(text string, importance widget.Importance) {
	f.clearCertificate()
	f.showStanding(text, importance)
}

// usesCard reports whether the key comes from a card or the Firefox store,
// both listed and opened the same way.
func (f *signForm) usesCard() bool {
	switch f.keySource.Selected {
	case f.m.KeyFromCard, f.m.KeyFromFirefox, f.m.KeyFromRemote:
		return true
	}
	return false
}

// keySourceChanged swaps the file and the card halves of the step. A pending
// file read is dropped: its answer would describe a certificate no longer in
// use.
func (f *signForm) keySourceChanged() {
	f.reading++
	f.clearCertificate()
	f.showStanding("", widget.LowImportance)
	f.remote.object().Hide()
	switch f.keySource.Selected {
	case f.m.KeyFromCard:
		f.showListedSource("card", f.cardList, f.m.NoCards, f.m.PINPlaceholder, f.m.SearchCards)
		return
	case f.m.KeyFromFirefox:
		f.showListedSource(domain.StoreFirefox, f.storeList, f.m.NoFirefoxCertificates, f.m.FirefoxPasswordPlaceholder, f.m.SearchCards)
		return
	case f.m.KeyFromRemote:
		f.remote.object().Show()
		f.showListedSource(domain.StoreRemote, f.remoteList, f.m.NoRemoteCredentials, f.m.RemotePINPlaceholder, f.m.SearchRemote)
		return
	}
	f.preferences.SetString(preferenceKeySource, "file")
	f.cards.object().Hide()
	f.fileSource.Show()
	f.readCertificate()
}

// showListedSource replaces the file half with the list of a card or store,
// remembering which source was chosen.
func (f *signForm) showListedSource(remembered string, list *application.ListCards, empty, pinName, search string) {
	f.preferences.SetString(preferenceKeySource, remembered)
	f.fileSource.Hide()
	f.cards.object().Show()
	f.cards.switchTo(list, empty, pinName, search)
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
		if f.keySource.Selected == f.m.KeyFromRemote {
			intent.Card.Account = f.remote.account()
		}
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
	// Each document of a batch takes the seal in its corner, never a field.
	f.offerFields(nil)
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
	if f.format == domain.FormatASiCE {
		// One container under one signature carries no seal.
		f.pages.withoutVisibleSeal()
		f.sealNote.Hide()
		f.invisible.Disable()
		return
	}
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
	if format == domain.FormatASiCE {
		// One signature over every document: one container, one command.
		base.DocumentPath, base.MoreDocuments, base.Format = documents[0], documents[1:], format
		f.signOne(base)
		return
	}
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
		Policy:            f.chosenPolicy(),
		Role:              f.chosenRole(),
		PDFPassword:       f.pdfPassword.Text,
	}
	f.keyIntent(&intent)
	if field, inField := f.chosenField(); inField {
		intent.Field = field.Name
	}
	switch {
	case f.format.HasVisibleSeal() && f.invisible.Checked:
		intent.Invisible = true
	case f.format.HasVisibleSeal():
		intent.Seal = f.pages.choice()
		intent.RubricPath = f.rubricPath
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
	f.signOne(intent)
}

// signOne signs off the UI thread and reports in place: one document, or
// one container over a batch.
func (f *signForm) signOne(intent domain.SigningIntent) {
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

// pdfNeedsPassword reports a PDF that does not open with the empty user
// password.
func pdfNeedsPassword(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false
	}
	_, err = pdflib.NewReader(file, info.Size())
	return errors.Is(err, pdflib.ErrInvalidPassword)
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
