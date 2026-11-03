//go:build gui

package infrastructure

// The verification tab renders the same report the CLI prints, so a user can
// check a signed file without leaving the app. It shells out to `firma-it
// verify --json` for the same reason the signing tab shells out to `sign`: one
// implementation, one set of findings, nothing to keep in sync.

import (
	"context"
	"encoding/json"
	"fmt"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/firma-it/src/desktop/messaging"
	"codeberg.org/simplicer/firma-it/src/verification/domain"
	reportmessaging "codeberg.org/simplicer/firma-it/src/verification/messaging"
)

// verifyReport mirrors the JSON emitted by `firma-it verify --json`.
type verifyReport struct {
	Path    string `json:"path"`
	Format  string `json:"format"`
	Signed  bool   `json:"signed"`
	Verdict string `json:"verdict"`
	Signers []struct {
		Field     string `json:"field"`
		Signer    string `json:"signer"`
		ID        string `json:"identifier"`
		Issuer    string `json:"issuer"`
		Format    string `json:"format"`
		SignedAt  string `json:"signed_at"`
		Timestamp bool   `json:"timestamped"`
		TSA       string `json:"timestamp_authority"`
		Integrity string `json:"integrity"`
		Trust     string `json:"trust"`
		Expired   bool   `json:"certificate_expired_now"`
		SelfSign  bool   `json:"self_signed"`
		Findings  []struct {
			Code    string `json:"code"`
			Status  string `json:"status"`
			Message string `json:"message"`
			Detail  string `json:"detail"`
		} `json:"findings"`
	} `json:"signers"`
	Warnings []struct {
		Code    string `json:"code"`
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"warnings"`
}

// verificationTab is the second tab of the window.
type verificationTab struct {
	window fyne.Window
	// ui holds the window strings (buttons, hints); report holds the wording of
	// the findings. Two catalogues because they answer different questions and
	// live in different slices.
	ui      messaging.Catalogue
	report  reportmessaging.Catalogue
	palette Palette
	binary  string

	pathEntry *widget.Entry
	output    *widget.Entry
	verdict   *canvas.Text
}

// newVerificationTab builds the tab.
func newVerificationTab(window fyne.Window, ui messaging.Catalogue, report reportmessaging.Catalogue, palette Palette, binary string) *verificationTab {
	return &verificationTab{window: window, ui: ui, report: report, palette: palette, binary: binary}
}

// content lays out the tab.
func (v *verificationTab) content() fyne.CanvasObject {
	v.pathEntry = widget.NewEntry()
	v.pathEntry.SetPlaceHolder("contratto_signed.pdf")

	v.verdict = canvas.NewText("", v.palette.TextMuted)
	v.verdict.TextSize = 16
	v.verdict.TextStyle = fyne.TextStyle{Bold: true}

	v.output = widget.NewMultiLineEntry()
	v.output.SetMinRowsVisible(18)
	v.output.Wrapping = fyne.TextWrapWord
	v.output.TextStyle = fyne.TextStyle{Monospace: true}

	choose := widget.NewButtonWithIcon(v.ui.ChooseButton, theme.FolderOpenIcon(), func() {
		pickFile(v.window, []string{".pdf", ".p7m", ".p7s", ".xml", ".xsig"}, v.pathEntry, nil)
	})

	check := widget.NewButtonWithIcon(v.ui.VerifyButton, theme.ConfirmIcon(), func() {
		v.run()
	})
	check.Importance = widget.HighImportance

	form := container.NewVBox(
		v.section(v.ui.VerifySection),
		widget.NewLabel(v.ui.VerifyHint),
		container.NewBorder(nil, nil, nil, choose, v.pathEntry),
		check,
		container.NewCenter(v.verdict),
		widget.NewSeparator(),
		v.output,
	)

	return container.NewPadded(container.NewVScroll(form))
}

// section renders a heading in the accent colour.
func (v *verificationTab) section(text string) fyne.CanvasObject {
	label := canvas.NewText(text, v.palette.Accent)
	label.TextSize = 15
	label.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewVBox(label, widget.NewSeparator())
}

// run executes the verification and renders the result.
func (v *verificationTab) run() {
	path := strings.TrimSpace(v.pathEntry.Text)
	if path == "" {
		v.verdict.Text = v.ui.MissingDocument
		v.verdict.Color = v.palette.Danger
		v.verdict.Refresh()
		return
	}

	v.verdict.Text = v.ui.SigningMessage
	v.verdict.Color = v.palette.TextMuted
	v.verdict.Refresh()
	v.output.SetText("")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		arguments := []string{"verify", path, "--json", "--offline", "--lang", languageCode(v.ui.Language)}
		raw, err := runCommand(ctx, v.binary, arguments)
		if err != nil && strings.TrimSpace(raw) == "" {
			fyne.Do(func() {
				v.verdict.Text = fmt.Sprintf("%v", err)
				v.verdict.Color = v.palette.Danger
				v.verdict.Refresh()
			})
			return
		}

		var report verifyReport
		if err := json.Unmarshal([]byte(raw), &report); err != nil {
			fyne.Do(func() {
				v.output.SetText(raw)
				v.verdict.Text = v.ui.VerificationUnreadable
				v.verdict.Color = v.palette.Danger
				v.verdict.Refresh()
			})
			return
		}

		fyne.Do(func() {
			v.render(report)
		})
	}()
}

// render prints the report in the window.
func (v *verificationTab) render(report verifyReport) {
	m := v.report

	v.verdict.Text = m.VerdictName(domain.TrustLevel(report.Verdict))
	v.verdict.Color = v.colourForVerdict(report.Verdict)
	v.verdict.Refresh()

	if !report.Signed {
		v.output.SetText(m.NoSignatures)
		return
	}

	var builder strings.Builder
	for index, signer := range report.Signers {
		fmt.Fprintf(&builder, "%s %d — %s\n", m.LabelSignature, index+1, signer.Field)
		fmt.Fprintf(&builder, "  %-14s %s\n", m.LabelSigner, signer.Signer)
		if signer.ID != "" {
			fmt.Fprintf(&builder, "  %-14s %s\n", m.LabelIdentifier, signer.ID)
		}
		if signer.Issuer != "" {
			fmt.Fprintf(&builder, "  %-14s %s\n", m.LabelIssuer, signer.Issuer)
		}
		if signer.SignedAt != "" {
			label := m.LabelSignedAt
			if signer.Timestamp {
				label = m.LabelTimestamped
			}
			fmt.Fprintf(&builder, "  %-14s %s\n", label, signer.SignedAt)
		}
		fmt.Fprintf(&builder, "  %-14s %s\n\n", m.LabelIntegrity, m.StatusName(domain.Status(signer.Integrity)))

		for _, finding := range signer.Findings {
			if finding.Status == "good" {
				continue
			}
			fmt.Fprintf(&builder, "  %s %s\n", m.StatusMark(domain.Status(finding.Status)),
				m.FindingName(finding.Code, finding.Message))
		}
		builder.WriteString("\n")
	}

	for _, warning := range report.Warnings {
		fmt.Fprintf(&builder, "  %s %s\n", m.StatusMark(domain.Status(warning.Status)),
			m.FindingName(warning.Code, warning.Message))
	}

	v.output.SetText(builder.String())
}

// colourForVerdict maps a verdict onto the palette.
//
// Colour is a second signal, never the only one: the verdict is also printed as
// text, because a colour-blind user must get the same information.
func (v *verificationTab) colourForVerdict(verdict string) color.Color {
	switch verdict {
	case "qualified", "advanced":
		return v.palette.Success
	case "broken":
		return v.palette.Danger
	case "untrusted":
		return v.palette.Danger
	}
	return v.palette.TextMuted
}

// languageCode maps the window language onto the CLI flag value.
func languageCode(language messaging.Language) string {
	switch language {
	case messaging.Italian:
		return "it"
	case messaging.English:
		return "en"
	}
	return "es"
}
