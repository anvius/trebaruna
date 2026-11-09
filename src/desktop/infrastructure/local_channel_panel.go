//go:build gui

package infrastructure

import (
	"context"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

// localChannelPanel explains the local channel's certificate, says whether
// it is installed, and installs or removes it on request.
type localChannelPanel struct {
	m       messaging.Catalogue
	manage  *application.ManageLocalChannel
	run     background
	root    *fyne.Container
	state   *widget.Label
	install *widget.Button
	remove  *widget.Button
}

func newLocalChannelPanel(m messaging.Catalogue, manage *application.ManageLocalChannel) *localChannelPanel {
	panel := &localChannelPanel{m: m, manage: manage, run: offThread, state: widget.NewLabel("")}
	explanation := widget.NewLabel(m.LocalChannelExplain)
	explanation.Wrapping = fyne.TextWrapWord
	panel.state.Wrapping = fyne.TextWrapWord
	panel.install = widget.NewButtonWithIcon(m.PageInstallLocalTLS, theme.ConfirmIcon(), func() { panel.act("install", "status") })
	panel.install.Importance = widget.HighImportance
	panel.remove = widget.NewButtonWithIcon(m.LocalChannelRemove, theme.DeleteIcon(), func() { panel.act("remove", "status") })
	panel.root = container.NewVBox(explanation, panel.state, container.NewHBox(panel.remove, layout.NewSpacer(), panel.install))
	return panel
}

// act runs the actions in turn, off the UI thread, and shows the last
// one's answer.
func (p *localChannelPanel) act(actions ...string) {
	p.install.Disable()
	p.remove.Disable()
	p.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		var output string
		var err error
		for _, action := range actions {
			if output, err = p.manage.Execute(ctx, action); err != nil {
				break
			}
		}
		fyne.Do(func() { p.show(output, err) })
	})
}

func (p *localChannelPanel) show(output string, err error) {
	p.install.Enable()
	p.remove.Enable()
	switch {
	case err != nil:
		p.state.Importance = widget.DangerImportance
		p.state.SetText(err.Error())
	case strings.Contains(output, ": installed"):
		p.state.Importance = widget.SuccessImportance
		p.state.SetText(p.m.LocalChannelInstalled)
	default:
		p.state.Importance = widget.MediumImportance
		p.state.SetText(p.m.LocalChannelNotInstalled)
	}
}
