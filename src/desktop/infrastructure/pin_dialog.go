//go:build gui

package infrastructure

import (
	"context"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// pinDialog asks for the secrets of a PIN change or a PUK unlock. It stays
// open on a refusal, so the person reads why before trying again; a refused
// secret is cleared, never offered for another try.
type pinDialog struct {
	action domain.PINAction
	token  string
	secret *widget.Entry
	newPIN *widget.Entry
	repeat *widget.Entry
	status *widget.Label
	apply  *widget.Button
	dialog *dialog.CustomDialog
	// closed is set once the dialog is gone, by success or by Cancel.
	closed bool
}

// showPINDialog opens the dialog for the card the form has chosen, or the
// only card present.
func (w *Window) showPINDialog(action domain.PINAction) *pinDialog {
	m := w.messages
	d := &pinDialog{
		action: action,
		token:  w.form.cardToken(),
		secret: widget.NewPasswordEntry(),
		newPIN: widget.NewPasswordEntry(),
		repeat: widget.NewPasswordEntry(),
		status: caption(""),
	}

	title, hint, secretLabel, confirm := m.ChangePINTitle, m.ChangePINHint, m.CurrentPINLabel, m.ChangePINButton
	newLabel, repeatLabel := m.NewPINLabel, m.RepeatPINLabel
	switch action {
	case domain.UnlockPIN:
		title, hint, secretLabel, confirm = m.UnlockPINTitle, m.UnlockPINHint, m.PUKLabel, m.UnlockPINButton
	case domain.ChangePUK:
		title, hint, secretLabel, confirm = m.ChangePUKTitle, m.ChangePUKHint, m.CurrentPUKLabel, m.ChangePUKButton
		newLabel, repeatLabel = m.NewPUKLabel, m.RepeatPUKLabel
	}
	card := m.PINDialogOnlyCard
	if d.token != "" {
		card = fmt.Sprintf(m.PINDialogCard, d.token)
	}
	explanation := widget.NewLabel(card + "\n" + hint)
	explanation.Wrapping = fyne.TextWrapWord

	d.apply = widget.NewButton(confirm, func() { w.applyPINChange(d) })
	d.apply.Importance = widget.HighImportance
	content := container.NewVBox(
		explanation,
		widget.NewForm(
			widget.NewFormItem(secretLabel, d.secret),
			widget.NewFormItem(newLabel, d.newPIN),
			widget.NewFormItem(repeatLabel, d.repeat),
		),
		d.status,
	)
	d.dialog = dialog.NewCustomWithoutButtons(title, content, w.window)
	d.dialog.SetButtons([]fyne.CanvasObject{widget.NewButton(m.CancelButton, d.dialog.Hide), d.apply})
	d.dialog.SetOnClosed(func() { d.closed = true })
	d.dialog.Resize(fyne.NewSize(460, 0))
	d.dialog.Show()
	w.window.Canvas().Focus(d.secret)
	return d
}

// applyPINChange runs the change off the UI thread and reports in place.
func (w *Window) applyPINChange(d *pinDialog) {
	m := w.messages
	change := domain.PINChange{
		Action: d.action, Token: d.token,
		Secret: d.secret.Text, NewPIN: d.newPIN.Text, Repeat: d.repeat.Text,
	}
	d.apply.Disable()
	d.status.Importance = widget.LowImportance
	d.status.SetText(m.TalkingToCard)

	w.form.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := w.pinChange.Execute(ctx, change)
		fyne.Do(func() {
			d.apply.Enable()
			if err != nil {
				d.status.Importance = widget.DangerImportance
				d.status.SetText(translate(err, m))
				if problem, ok := err.(domain.Problem); ok && problem.StopsCard() {
					d.secret.SetText("")
				}
				return
			}
			d.dialog.Hide()
			done := m.PINChanged
			switch d.action {
			case domain.UnlockPIN:
				done = m.CardUnlocked
			case domain.ChangePUK:
				done = m.PUKChanged
			}
			dialog.ShowInformation(m.MenuCard, done, w.window)
			w.form.cardsChanged()
		})
	})
}
