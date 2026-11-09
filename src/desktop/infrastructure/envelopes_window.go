//go:build gui

package infrastructure

import (
	"context"
	"fmt"
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
)

// recipientExtensions are the certificate files an envelope is encrypted for.
var recipientExtensions = []string{".pem", ".cer", ".crt", ".der"}

// chosenKey is the key chosen to sign, ready to open an envelope, and the
// name of its holder; ok is false while none is chosen.
type chosenKey func() (key domain.OpeningIntent, holder string, ok bool)

// envelopesPanel encrypts a document for the people whose certificates are
// added, and opens an envelope sent to the person with the key chosen to
// sign. Envelopes are rare next to signatures, so the panel is a window
// opened from the File menu, not a third tab (see withTabs).
type envelopesPanel struct {
	window  fyne.Window
	m       messaging.Catalogue
	palette Palette
	encrypt *application.EncryptForRecipients
	open    *application.OpenEnvelope
	inspect *application.InspectCertificate
	key     chosenKey
	// chooseKey takes the person to step 2 of the signing tab.
	chooseKey func()
	// refused lets the signing tab read the card again after a refusal.
	refused func(error)
	run     background

	document      *fileRow
	documentPath  string
	recipients    []recipient
	recipientList *fyne.Container
	// book is the address book; saved its recipients, offered in savedList;
	// keepBook keeps the recipients of an envelope once it is made.
	book      *application.ManageRecipientBook
	saved     []domain.SavedRecipient
	savedList *fyne.Container
	keepBook  *widget.Check
	// bookStatus says what went wrong with the book, apart from the
	// envelope\'s own outcome.
	bookStatus    *widget.Label
	encryptButton *widget.Button
	encryptStatus *widget.Label

	envelope     *fileRow
	envelopePath string
	keyLine      *widget.Label
	// keyRow offers to choose a key while none is chosen.
	keyRow     *fyne.Container
	openButton *widget.Button
	openStatus *widget.Label
	// openedRow shows the document just taken out.
	openedRow *fyne.Container
	opened    string
}

// recipient is a certificate the document is encrypted for.
type recipient struct {
	path, holder string
}

func newEnvelopesPanel(window fyne.Window, m messaging.Catalogue, palette Palette) *envelopesPanel {
	p := &envelopesPanel{window: window, m: m, palette: palette, run: offThread}
	p.document = newFileRow(m.ChooseDocument, m.ChangeButton, "", func() {
		newFileOpen(p.window, nil, p.setDocument).Show()
	})
	p.recipientList = container.NewVBox()
	p.savedList = container.NewVBox()
	p.keepBook = widget.NewCheck(m.KeepRecipients, nil)
	p.keepBook.SetChecked(true)
	p.bookStatus = statusLabel()
	p.encryptButton = widget.NewButtonWithIcon(m.EncryptButton, theme.VisibilityOffIcon(), p.encryptDocument)
	p.encryptButton.Importance = widget.HighImportance
	p.encryptStatus = statusLabel()

	p.envelope = newFileRow(m.ChooseEnvelope, m.ChangeButton, m.EnvelopeHint, func() {
		newFileOpen(p.window, []string{".p7e"}, p.setEnvelope).Show()
	})
	p.keyLine = widget.NewLabel("")
	p.keyLine.Wrapping = fyne.TextWrapWord
	p.keyRow = container.NewHBox(widget.NewButtonWithIcon(m.GoToCertificate, theme.AccountIcon(), func() {
		if p.chooseKey != nil {
			p.chooseKey()
		}
	}))
	p.openButton = widget.NewButtonWithIcon(m.OpenEnvelopeButton, theme.VisibilityIcon(), p.openEnvelope)
	p.openButton.Importance = widget.HighImportance
	p.openStatus = statusLabel()
	p.openedRow = container.NewHBox(widget.NewButtonWithIcon(m.OpenSigned, theme.FileIcon(), func() { openWithSystemViewer(p.opened) }))
	p.openedRow.Hide()
	p.showRecipients()
	return p
}

// statusLabel is a half's outcome line, hidden while it has nothing to say.
func statusLabel() *widget.Label {
	label := widget.NewLabel("")
	label.Wrapping = fyne.TextWrapWord
	label.Hide()
	return label
}

// content lays out the two halves side by side, each with its button in
// sight: encrypting on the left, what a person does on their own
// initiative, opening what others did on the right.
func (p *envelopesPanel) content() fyne.CanvasObject {
	encrypting := container.NewVBox(
		p.heading(p.m.EncryptSection),
		caption(p.m.EncryptIntro),
		p.document.object(),
		fieldLabel(p.m.RecipientsLabel),
		p.recipientList,
		container.NewHBox(widget.NewButtonWithIcon(p.m.AddRecipient, theme.ContentAddIcon(), func() {
			newFileOpen(p.window, recipientExtensions, p.addRecipient).Show()
		})),
		fieldLabel(p.m.SavedRecipientsLabel),
		p.savedList,
		p.bookStatus,
		p.keepBook,
		p.encryptStatus,
		p.encryptButton,
	)
	opening := container.NewVBox(
		p.heading(p.m.OpenSection),
		p.envelope.object(),
		p.keyLine,
		p.keyRow,
		p.openStatus,
		p.openedRow,
		p.openButton,
	)
	p.refreshKey()
	return container.NewHSplit(
		container.NewVScroll(container.NewPadded(encrypting)),
		container.NewVScroll(container.NewPadded(opening)),
	)
}

func (p *envelopesPanel) heading(text string) fyne.CanvasObject {
	heading := canvas.NewText(text, p.palette.Text)
	heading.TextSize = 16
	heading.TextStyle = fyne.TextStyle{Bold: true}
	return heading
}

// ---- encrypting ----

func (p *envelopesPanel) setDocument(path string) {
	p.documentPath = path
	p.document.show(path, "")
	p.report(p.encryptStatus, "", widget.LowImportance)
}

// addRecipient reads the certificate before listing it: the holder's name
// is what the person checks, and a file that is no certificate is refused
// here rather than when encrypting.
func (p *envelopesPanel) addRecipient(path string) {
	for _, listed := range p.recipients {
		if listed.path == path {
			return
		}
	}
	p.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		summary, err := p.inspect.Execute(ctx, domain.CertificateFile{Path: path})
		fyne.Do(func() {
			if err != nil {
				p.report(p.encryptStatus, translate(err, p.m), widget.DangerImportance)
				return
			}
			p.recipients = append(p.recipients, recipient{path: path, holder: summary.Holder})
			p.report(p.encryptStatus, "", widget.LowImportance)
			p.showRecipients()
		})
	})
}

func (p *envelopesPanel) removeRecipient(path string) {
	kept := p.recipients[:0]
	for _, listed := range p.recipients {
		if listed.path != path {
			kept = append(kept, listed)
		}
	}
	p.recipients = kept
	p.showRecipients()
}

// changeBook keeps or forgets recipients off the UI thread, then shows the
// book as it is; with no change it only reads it.
func (p *envelopesPanel) changeBook(change domain.RecipientBookChange) {
	if p.book == nil {
		return
	}
	p.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		saved, err := p.book.Execute(ctx, change)
		fyne.Do(func() {
			reading := len(change.Keep) == 0 && change.Forget == ""
			switch {
			case err != nil && reading:
				// A book that cannot be read leaves the list empty; encrypting
				// for files still works.
				return
			case err != nil:
				p.report(p.bookStatus, translate(err, p.m), widget.DangerImportance)
				return
			}
			p.report(p.bookStatus, "", widget.LowImportance)
			p.saved = saved
			p.showSaved()
		})
	})
}

// showSaved offers each saved recipient not chosen yet: its holder, until
// when it serves, to add with one click or forget.
func (p *envelopesPanel) showSaved() {
	p.savedList.Objects = nil
	chosen := map[string]bool{}
	for _, listed := range p.recipients {
		chosen[listed.path] = true
	}
	shown := 0
	for _, saved := range p.saved {
		if chosen[saved.Path] {
			continue
		}
		shown++
		saved := saved
		name := widget.NewLabelWithStyle(saved.Holder, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		name.Wrapping = fyne.TextWrapWord
		validity := caption(fmt.Sprintf(p.m.SavedUntil, saved.NotAfter.Format("02/01/2006")))
		add := widget.NewButtonWithIcon(p.m.UseSavedRecipient, theme.ContentAddIcon(), func() {
			p.recipients = append(p.recipients, recipient{path: saved.Path, holder: saved.Holder})
			p.showRecipients()
		})
		if time.Now().After(saved.NotAfter) {
			validity = caption(fmt.Sprintf(p.m.SavedExpired, saved.NotAfter.Format("02/01/2006")))
			validity.Importance = widget.DangerImportance
			add.Disable()
		}
		forget := widget.NewButtonWithIcon(p.m.ForgetRecipient, theme.DeleteIcon(), func() {
			p.changeBook(domain.RecipientBookChange{Forget: saved.Fingerprint})
		})
		details := container.New(layout.NewCustomPaddedVBoxLayout(0), name, validity)
		p.savedList.Add(container.NewBorder(nil, nil, nil, container.NewHBox(add, forget), details))
	}
	if shown == 0 {
		p.savedList.Add(caption(p.m.NoSavedRecipients))
	}
	p.savedList.Refresh()
}

// showRecipients lists each recipient by name, with the file it came from.
func (p *envelopesPanel) showRecipients() {
	p.recipientList.Objects = nil
	if len(p.recipients) == 0 {
		p.recipientList.Add(caption(p.m.NoRecipients))
	}
	for _, listed := range p.recipients {
		path := listed.path
		name := widget.NewLabelWithStyle(listed.holder, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		name.Wrapping = fyne.TextWrapWord
		remove := widget.NewButtonWithIcon(p.m.RemoveRecipient, theme.ContentRemoveIcon(), func() { p.removeRecipient(path) })
		details := container.New(layout.NewCustomPaddedVBoxLayout(0), name, caption(filepath.Base(path)))
		p.recipientList.Add(container.NewBorder(nil, nil, nil, container.NewVBox(remove), details))
	}
	p.recipientList.Refresh()
	p.showSaved()
}

func (p *envelopesPanel) encryptDocument() {
	intent := domain.EncryptionIntent{DocumentPath: p.documentPath}
	for _, listed := range p.recipients {
		intent.Recipients = append(intent.Recipients, listed.path)
	}
	if err := intent.Validate(); err != nil {
		p.report(p.encryptStatus, translate(err, p.m), widget.DangerImportance)
		return
	}
	p.encryptButton.Disable()
	p.report(p.encryptStatus, p.m.EncryptingMessage, widget.LowImportance)
	p.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		sealed, err := p.encrypt.Execute(ctx, intent)
		fyne.Do(func() {
			p.encryptButton.Enable()
			if err != nil {
				p.report(p.encryptStatus, translate(err, p.m), widget.DangerImportance)
				return
			}
			// The names the command encrypted for, as it read them.
			p.report(p.encryptStatus, fmt.Sprintf(p.m.EncryptedAs, filepath.Base(sealed.Path), strings.Join(sealed.Recipients, ", ")),
				widget.SuccessImportance)
			if p.keepBook.Checked {
				p.keepNewRecipients()
			}
		})
	})
}

// keepNewRecipients saves the recipients chosen from files, not those
// already in the book.
func (p *envelopesPanel) keepNewRecipients() {
	inBook := map[string]bool{}
	for _, saved := range p.saved {
		inBook[saved.Path] = true
	}
	var fresh []string
	for _, listed := range p.recipients {
		if !inBook[listed.path] {
			fresh = append(fresh, listed.path)
		}
	}
	if len(fresh) > 0 {
		p.changeBook(domain.RecipientBookChange{Keep: fresh})
	}
}

// ---- opening ----

// setEnvelope chooses the envelope to open, from the dialog, a drop on the
// main window or the file the app was opened with.
func (p *envelopesPanel) setEnvelope(path string) {
	p.envelopePath = path
	p.envelope.show(path, "")
	p.openedRow.Hide()
	p.report(p.openStatus, "", widget.LowImportance)
	p.refreshKey()
}

// refreshKey says which key will open the envelope, or how to choose one.
func (p *envelopesPanel) refreshKey() {
	if p.key == nil {
		return
	}
	if _, holder, ok := p.key(); ok {
		p.keyLine.SetText(fmt.Sprintf(p.m.OpensWith, holder))
		p.keyRow.Hide()
		return
	}
	p.keyLine.SetText(p.m.NoKeyToOpen)
	p.keyRow.Show()
}

func (p *envelopesPanel) openEnvelope() {
	p.refreshKey()
	intent, _, _ := p.key()
	intent.EnvelopePath = p.envelopePath
	if err := intent.Validate(); err != nil {
		p.report(p.openStatus, translate(err, p.m), widget.DangerImportance)
		return
	}
	p.openButton.Disable()
	p.openedRow.Hide()
	p.report(p.openStatus, p.m.OpeningMessage, widget.LowImportance)
	p.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		opened, err := p.open.Execute(ctx, intent)
		fyne.Do(func() {
			p.openButton.Enable()
			if err != nil {
				p.report(p.openStatus, translate(err, p.m), widget.DangerImportance)
				if p.refused != nil {
					p.refused(err)
				}
				return
			}
			p.opened = opened.Path
			p.report(p.openStatus, fmt.Sprintf(p.m.OpenedAs, filepath.Base(opened.Path), readableSize(opened.Size)),
				widget.SuccessImportance)
			p.openedRow.Show()
		})
	})
}

func (p *envelopesPanel) report(label *widget.Label, text string, importance widget.Importance) {
	label.Importance = importance
	label.SetText(text)
	label.Hidden = text == ""
	label.Refresh()
}
