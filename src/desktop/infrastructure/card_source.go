//go:build gui

package infrastructure

import (
	"context"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// preferenceCardCertificate remembers the fingerprint of the card certificate
// last chosen. It names a certificate, never a PIN.
const preferenceCardCertificate = "card.fingerprint"

// cardSource is the card half of the certificate step: the certificates of
// the cards in the readers, the PIN, and what each card says about its
// attempts before anyone types it.
//
// The cards are listed without a PIN, so looking never spends an attempt; a
// locked card is stated, and the form refuses to sign with it.
type cardSource struct {
	m           messaging.Catalogue
	list        *application.ListCards
	preferences fyne.Preferences
	// onChosen fills the certificate card from the certificate chosen;
	// onEmpty reports why there is none.
	onChosen func(domain.CardCertificate)
	onEmpty  func(text string, importance widget.Importance)

	certificates []domain.CardCertificate
	chosen       *domain.CardCertificate
	searching    int
	run          background

	choice *widget.RadioGroup
	search *widget.Button
	where  *widget.Label
	pin    *widget.Entry
	note   *widget.Label
	root   *fyne.Container
}

func newCardSource(
	m messaging.Catalogue,
	list *application.ListCards,
	preferences fyne.Preferences,
	onChosen func(domain.CardCertificate),
	onEmpty func(string, widget.Importance),
) *cardSource {
	source := &cardSource{m: m, list: list, preferences: preferences, onChosen: onChosen, onEmpty: onEmpty, run: offThread}

	// A list, not a drop-down: a drop-down cuts a long name to fit its width,
	// and every certificate of the card stays in sight, which is the point of
	// choosing between them.
	source.choice = widget.NewRadioGroup(nil, source.choose)
	source.search = widget.NewButtonWithIcon(m.SearchCards, theme.ViewRefreshIcon(), source.refresh)
	source.where = caption("")
	source.pin = widget.NewPasswordEntry()
	source.pin.SetPlaceHolder(m.PINPlaceholder)
	source.note = caption("")
	source.note.Hide()

	source.root = container.NewVBox(
		source.choice,
		source.where,
		source.pin,
		source.note,
		container.NewHBox(source.search),
	)
	return source
}

func (c *cardSource) object() fyne.CanvasObject { return c.root }

// key is the certificate chosen with the PIN typed, or no key at all.
func (c *cardSource) key() domain.CardKey {
	if c.chosen == nil {
		return domain.CardKey{}
	}
	return c.chosen.Key(c.pin.Text)
}

// refresh lists the cards again, off the UI thread.
func (c *cardSource) refresh() {
	c.searching++
	ticket := c.searching
	c.search.Disable()
	c.onEmpty(c.m.CardsSearching, widget.LowImportance)

	c.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		certificates, err := c.list.Execute(ctx)
		fyne.Do(func() {
			if ticket != c.searching {
				return
			}
			c.search.Enable()
			c.listed(certificates, err)
		})
	})
}

// listed offers the certificates found, keeping the one chosen before (or
// remembered from another day), else the one the card signs with.
func (c *cardSource) listed(certificates []domain.CardCertificate, err error) {
	previous := c.preferences.String(preferenceCardCertificate)
	if c.chosen != nil {
		previous = c.chosen.Fingerprint
	}
	c.certificates = certificates
	c.chosen = nil
	c.choice.Options = c.labels()
	c.choice.Selected = ""
	c.choice.Refresh()
	c.where.SetText("")

	switch {
	case err != nil:
		c.onEmpty(err.Error(), widget.DangerImportance)
		return
	case len(certificates) == 0:
		c.onEmpty(c.m.NoCards, widget.MediumImportance)
		return
	}

	selected := -1
	for index, certificate := range certificates {
		if certificate.Fingerprint == previous {
			selected = index
			break
		}
		if selected < 0 && certificate.SignsByDefault {
			selected = index
		}
	}
	if selected < 0 {
		c.onEmpty(c.m.CardPlaceholder, widget.MediumImportance)
		return
	}
	c.choice.SetSelected(c.choice.Options[selected])
}

// labels names each certificate by its holder. Two certificates with the
// same holder, as an authentication and a signature certificate on one card
// often are, also say which one signs; a label that still repeats gets the
// start of its fingerprint, so two identical cards stay apart.
func (c *cardSource) labels() []string {
	holders := map[string]int{}
	for _, certificate := range c.certificates {
		holders[certificate.Summary.Holder]++
	}

	labels := make([]string, len(c.certificates))
	seen := map[string]bool{}
	for index, certificate := range c.certificates {
		label := certificate.Summary.Holder
		if holders[label] > 1 {
			role := c.m.CardOtherRole
			if certificate.SignsByDefault {
				role = c.m.CardSigningRole
			}
			label = fmt.Sprintf("%s (%s)", label, role)
		}
		if seen[label] {
			label += " " + certificate.Fingerprint[:min(8, len(certificate.Fingerprint))]
		}
		seen[label] = true
		labels[index] = label
	}
	return labels
}

// choose adopts the certificate behind a label.
func (c *cardSource) choose(label string) {
	index := indexOf(c.choice.Options, label)
	if index < 0 {
		return
	}
	certificate := c.certificates[index]
	c.chosen = &certificate
	c.preferences.SetString(preferenceCardCertificate, certificate.Fingerprint)
	c.where.SetText(fmt.Sprintf(c.m.CardWhere, certificate.Token, certificate.Reader))
	c.showPINState(certificate)
	c.onChosen(certificate)
}

// showPINState says what the card says about its PIN, when it says anything
// worth knowing before typing it.
func (c *cardSource) showPINState(certificate domain.CardCertificate) {
	text, importance := "", widget.LowImportance
	switch certificate.PIN {
	case signing.PINCountLow:
		text, importance = c.m.PINCountLow, widget.WarningImportance
	case signing.PINFinalTry:
		text, importance = c.m.PINFinalTry, widget.DangerImportance
	case signing.PINLocked:
		text, importance = c.m.CardLocked, widget.DangerImportance
	case signing.PINToBeChanged, signing.PINNotSet:
		text, importance = c.m.PINExpired, widget.DangerImportance
	}
	if certificate.PINPad {
		text = joinSentences(text, c.m.PINPadHint)
	}
	c.note.Importance = importance
	c.note.SetText(text)
	c.note.Hidden = text == ""
	c.note.Refresh()

	usable := certificate.PIN.CanSign() && certificate.PIN != signing.PINNotRequired && !certificate.PINPad
	if usable {
		c.pin.Enable()
	} else {
		c.pin.SetText("")
		c.pin.Disable()
	}
}

// refused clears a PIN the card did not take and reads the cards again, so
// the attempts left are shown before the next try.
func (c *cardSource) refused() {
	c.pin.SetText("")
	c.refresh()
}

// indexOf finds a string in a list, or -1.
func indexOf(values []string, wanted string) int {
	for index, value := range values {
		if value == wanted {
			return index
		}
	}
	return -1
}

// joinSentences puts two sentences on separate lines, skipping an empty one.
func joinSentences(first, second string) string {
	switch {
	case first == "":
		return second
	case second == "":
		return first
	}
	return first + "\n" + second
}
