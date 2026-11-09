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
	pages       *pagePane
	// onCheck hands a signed file to the verification tab.
	onCheck func(path string)
	// onNetwork receives the connections a signature reported.
	onNetwork func([]transparency.Connection)

	document string
	// fingerprint is the SHA-256 shown for the document; the receipt must
	// report the same one, or the file changed between choosing and signing.
	fingerprint string
	certificate string
	format      domain.SignatureFormat
	summary     *domain.CertificateSummary
	reading     int
	debounce    *time.Timer

	documentRow    *fileRow
	certificateRow *fileRow
	passphrase     *widget.Entry
	holder         *widget.Label
	holderDetails  *widget.Label
	standing       *widget.Label
	formatChoice   *widget.RadioGroup
	formatNote     *widget.Label
	sealNote       *widget.Label
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
	pages *pagePane,
) *signForm {
	form := &signForm{
		window: window, m: m, palette: palette, preferences: preferences,
		signing: signing, inspect: inspect, pages: pages,
		format: domain.FormatPAdES,
	}

	form.documentRow = newFileRow(m.ChooseDocument, m.ChangeButton, m.DropHint, form.pickDocument)
	form.certificateRow = newFileRow(m.ChooseCertificate, m.ChangeButton, m.CertificateHint, form.pickCertificate)

	form.passphrase = widget.NewPasswordEntry()
	form.passphrase.SetPlaceHolder(m.PassphrasePlaceholder)
	form.passphrase.OnChanged = func(string) { form.readCertificateSoon() }
	form.passphrase.OnSubmitted = func(string) { form.readCertificate() }

	form.holder = widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	form.holder.Wrapping = fyne.TextWrapWord
	form.holderDetails = caption("")
	form.standing = widget.NewLabel("")
	form.standing.Wrapping = fyne.TextWrapWord

	form.formatChoice = widget.NewRadioGroup(nil, func(label string) { form.chooseFormat(label) })
	form.formatChoice.Required = true
	form.formatNote = caption("")
	form.sealNote = caption("")

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
		f.certificateRow.object(),
		f.passphrase,
		card,
		f.step(3, m.StepSignature),
		f.formatChoice,
		f.formatNote,
		f.sealNote,
		widget.NewAccordion(widget.NewAccordionItem(m.MoreOptions, container.NewVBox(
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
	f.document = path
	f.fingerprint = ""
	go f.measure(path)
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

	if f.format.HasVisibleSeal() {
		f.pages.show(f.document)
		f.sealNote.SetText(f.m.SealOnPagePane)
		f.sealNote.Show()
		return
	}
	f.pages.withoutVisibleSeal()
	f.sealNote.Hide()
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
		return f.m.FormatCAdESLabel
	case domain.FormatXAdES:
		return f.m.FormatXAdESLabel
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
	f.debounce = time.AfterFunc(600*time.Millisecond, func() { fyne.Do(f.readCertificate) })
}

// readCertificate fills the certificate card from the certificate itself.
func (f *signForm) readCertificate() {
	if f.certificate == "" {
		return
	}
	f.reading++
	ticket := f.reading
	file := domain.CertificateFile{Path: f.certificate, Passphrase: f.passphrase.Text}
	f.showStanding(f.m.CertificateReading, widget.LowImportance)

	go func() {
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
	}()
}

func (f *signForm) certificateFailed(err error, withoutPassphrase bool) {
	f.summary = nil
	f.holder.SetText("")
	f.holderDetails.SetText("")
	f.pages.setIdentity(SealIdentity{})

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

// ---- signing ----

// sign validates, signs off the UI thread, and reports in place.
func (f *signForm) sign() {
	intent := domain.SigningIntent{
		DocumentPath:      f.document,
		Key:               domain.CertificateFile{Path: f.certificate, Passphrase: f.passphrase.Text},
		Format:            f.format,
		Level:             f.selectedLevel(),
		Seal:              domain.SealChoice{Page: 1},
		TimestampURL:      strings.TrimSpace(f.timestamp.Text),
		TimestampUser:     strings.TrimSpace(f.tsaUser.Text),
		TimestampPassword: f.tsaPassword.Text,
		Reason:            strings.TrimSpace(f.reason.Text),
		Location:          strings.TrimSpace(f.location.Text),
	}
	if f.format.HasVisibleSeal() {
		intent.Seal = f.pages.choice()
	}
	if err := intent.Validate(); err != nil {
		f.report(translate(err, f.m), widget.DangerImportance)
		return
	}

	f.signButton.Disable()
	f.afterSign.Hide()
	f.report(f.m.SigningMessage, widget.LowImportance)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		receipt, err := f.signing.Execute(ctx, intent)

		fyne.Do(func() {
			f.signButton.Enable()
			if err != nil {
				f.report(translate(err, f.m), widget.DangerImportance)
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
	}()
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
