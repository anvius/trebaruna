//go:build gui

package infrastructure

// The verification tab renders the same report the CLI prints, so a user can
// check a signed file without leaving the app. It shells out to `trebaruna
// verify --json` for the same reason the signing tab shells out to `sign`: one
// implementation, one set of findings, nothing to keep in sync.

import (
	"context"
	"encoding/json"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	reportmessaging "codeberg.org/simplicer/trebaruna/src/verification/messaging"

	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
)

// verifyReport mirrors the JSON emitted by `trebaruna verify --json`.
type verifyReport struct {
	Path    string `json:"path"`
	Format  string `json:"format"`
	Signed  bool   `json:"signed"`
	Verdict string `json:"verdict"`
	Signers []struct {
		Field        string `json:"field"`
		Countersigns string `json:"countersigns"`
		Signer       string `json:"signer"`
		ID           string `json:"identifier"`
		Issuer       string `json:"issuer"`
		Format       string `json:"format"`
		SignedAt     string `json:"signed_at"`
		Timestamp    bool   `json:"timestamped"`
		TSA          string `json:"timestamp_authority"`
		Integrity    string `json:"integrity"`
		Trust        string `json:"trust"`
		Expired      bool   `json:"certificate_expired_now"`
		SelfSign     bool   `json:"self_signed"`
		Findings     []struct {
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
	Network []transparency.Connection `json:"network"`
}

// signedExtensions are the containers a signed document arrives in.
var signedExtensions = []string{".pdf", ".p7m", ".p7s", ".xml", ".xsig", ".asice", ".asics"}

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

	file *fileRow
	path string
	// onNetwork receives the connections a check reported.
	onNetwork   func([]transparency.Connection)
	online      *widget.Check
	check       *widget.Button
	verdict     *canvas.Text
	explanation *widget.Label
	signers     *fyne.Container
	extract     *widget.Button
	extracted   *widget.Label
	// open shows a file in the system viewer; tests replace it.
	open func(path string)
}

// newVerificationTab builds the tab.
func newVerificationTab(window fyne.Window, ui messaging.Catalogue, report reportmessaging.Catalogue, palette Palette, binary string) *verificationTab {
	return &verificationTab{window: window, ui: ui, report: report, palette: palette, binary: binary, open: openWithSystemViewer}
}

// content lays out the tab: what to check, then what was found.
func (v *verificationTab) content() fyne.CanvasObject {
	v.file = newFileRow(v.ui.ChooseDocument, v.ui.ChangeButton, v.ui.VerifyHint, func() {
		newFileOpen(v.window, signedExtensions, v.verifyFile).Show()
	})

	v.online = widget.NewCheck(v.ui.OnlineRevocation, func(bool) {
		if v.path != "" {
			v.run()
		}
	})
	v.check = widget.NewButtonWithIcon(v.ui.VerifyButton, theme.SearchIcon(), v.run)
	v.check.Importance = widget.HighImportance

	v.verdict = canvas.NewText("", v.palette.TextMuted)
	v.verdict.TextSize = 22
	v.verdict.TextStyle = fyne.TextStyle{Bold: true}
	v.explanation = widget.NewLabel("")
	v.explanation.Wrapping = fyne.TextWrapWord
	v.signers = container.NewVBox()
	v.extract = widget.NewButtonWithIcon(v.ui.ExtractButton, theme.DownloadIcon(), v.extractDocument)
	v.extract.Hide()
	v.extracted = widget.NewLabel("")
	v.extracted.Wrapping = fyne.TextWrapWord
	v.extracted.Hide()

	heading := canvas.NewText(v.ui.VerifySection, v.palette.Text)
	heading.TextSize = 16
	heading.TextStyle = fyne.TextStyle{Bold: true}

	column := container.NewVBox(
		heading,
		v.file.object(),
		v.online,
		v.check,
		widget.NewSeparator(),
		v.verdict,
		v.explanation,
		v.extract,
		v.extracted,
		v.signers,
	)
	// A reading column, not a full-width sheet: findings are prose, and lines
	// of 160 characters are not read, they are skimmed.
	return container.NewVScroll(container.NewPadded(container.New(readingColumn{width: 760}, column)))
}

// verifyFile checks a file chosen elsewhere: the file dialog, a drop on the
// window, or the signing tab right after a signature.
func (v *verificationTab) verifyFile(path string) {
	v.path = path
	v.file.show(path, "")
	v.run()
}

// run executes the verification and renders the result.
func (v *verificationTab) run() {
	if strings.TrimSpace(v.path) == "" {
		v.showVerdict(v.ui.MissingDocument, "", v.palette.Danger)
		return
	}

	v.showVerdict(v.ui.CheckingMessage, "", v.palette.TextMuted)
	v.signers.Objects = nil
	v.signers.Refresh()
	v.check.Disable()

	path, offline := v.path, !v.online.Checked
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		arguments := []string{"verify", path, "--json", fmt.Sprintf("--offline=%t", offline), "--lang", languageCode(v.ui.Language)}
		raw, err := runCommand(ctx, v.binary, arguments)

		var report verifyReport
		decodeErr := json.Unmarshal([]byte(raw), &report)
		fyne.Do(func() {
			v.check.Enable()
			switch {
			case err != nil && strings.TrimSpace(raw) == "":
				v.showVerdict(err.Error(), "", v.palette.Danger)
			case decodeErr != nil:
				v.showVerdict(v.ui.VerificationUnreadable, strings.TrimSpace(raw), v.palette.Danger)
			default:
				v.render(report)
			}
		})
	}()
}

func (v *verificationTab) showVerdict(verdict, explanation string, colour color.Color) {
	v.verdict.Text = verdict
	v.verdict.Color = colour
	v.verdict.Refresh()
	v.explanation.SetText(explanation)
}

// render shows the verdict in words, then one block per signature.
func (v *verificationTab) render(report verifyReport) {
	m := v.report
	verdict := domain.TrustLevel(report.Verdict)
	v.extracted.Hide()
	if isEnvelope(v.path) {
		v.extract.Show()
	} else {
		v.extract.Hide()
	}
	if v.onNetwork != nil && len(report.Network) > 0 {
		v.onNetwork(report.Network)
	}

	if !report.Signed {
		v.showVerdict(m.NoSignatures, "", v.palette.TextMuted)
		return
	}
	// The verdict is a word and a sentence, and the colour only repeats it: a
	// colour-blind user must get the same answer.
	v.showVerdict(m.VerdictName(verdict), v.explain(verdict), v.colourFor(verdict))

	blocks := make([]fyne.CanvasObject, 0, len(report.Signers)+1)
	for _, signer := range report.Signers {
		name := widget.NewLabelWithStyle(signer.Signer, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		name.Wrapping = fyne.TextWrapWord

		var facts []string
		if signer.Countersigns != "" {
			facts = append(facts, fmt.Sprintf(v.ui.CountersignatureOf, signer.Countersigns))
		}
		if signer.ID != "" {
			facts = append(facts, m.LabelIdentifier+": "+signer.ID)
		}
		if signer.Issuer != "" {
			facts = append(facts, m.LabelIssuer+": "+signer.Issuer)
		}
		if signer.SignedAt != "" {
			label := m.LabelSignedAt
			if signer.Timestamp {
				label = m.LabelTimestamped
			}
			facts = append(facts, label+": "+readableInstant(signer.SignedAt))
		}
		facts = append(facts, m.LabelIntegrity+": "+m.StatusName(domain.Status(signer.Integrity)))

		var findings []string
		for _, finding := range signer.Findings {
			if finding.Status == "good" {
				continue
			}
			findings = append(findings, m.StatusMark(domain.Status(finding.Status))+" "+m.FindingName(finding.Code, finding.Message))
		}

		block := container.NewVBox(widget.NewSeparator(), name, caption(strings.Join(facts, "\n")))
		if len(findings) > 0 {
			list := widget.NewLabel(strings.Join(findings, "\n"))
			list.Wrapping = fyne.TextWrapWord
			block.Add(list)
		}
		blocks = append(blocks, block)
	}

	var warnings []string
	for _, warning := range report.Warnings {
		warnings = append(warnings, m.StatusMark(domain.Status(warning.Status))+" "+m.FindingName(warning.Code, warning.Message))
	}
	if len(warnings) > 0 {
		blocks = append(blocks, widget.NewSeparator(), caption(strings.Join(warnings, "\n")))
	}

	v.signers.Objects = blocks
	v.signers.Refresh()
}

// readableInstant writes a signing time the way the seal prints it, keeping
// the offset; anything unparsable is shown as received.
func readableInstant(value string) string {
	instant, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return instant.Format("02/01/2006 15:04:05 -07:00")
}

// explain says in one sentence what the verdict means for the document.
func (v *verificationTab) explain(verdict domain.TrustLevel) string {
	switch verdict {
	case "qualified":
		return v.ui.ExplainQualified
	case "advanced":
		return v.ui.ExplainAdvanced
	case "untrusted":
		return v.ui.ExplainUntrusted
	case "invalid":
		return v.ui.ExplainInvalid
	case "broken":
		return v.ui.ExplainBroken
	}
	return v.ui.ExplainUnknown
}

// colourFor separates "the document changed" and "the signer had no right to
// sign" (red) from "nobody vouches for the issuer" (amber): the first two are
// failures, the third is missing evidence.
func (v *verificationTab) colourFor(verdict domain.TrustLevel) color.Color {
	switch verdict {
	case "qualified", "advanced":
		return v.palette.Success
	case "broken", "invalid":
		return v.palette.Danger
	case "untrusted", "unknown":
		return v.palette.Warning
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

// readingColumn centres one child and caps its width, so text keeps a
// readable measure on a wide window while still shrinking on a narrow one.
type readingColumn struct {
	width float32
}

// Layout places the child in the middle, no wider than the column.
func (c readingColumn) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	width := min(size.Width, c.width)
	for _, object := range objects {
		object.Resize(fyne.NewSize(width, size.Height))
		object.Move(fyne.NewPos((size.Width-width)/2, 0))
	}
}

// MinSize is the child's own minimum.
func (c readingColumn) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var size fyne.Size
	for _, object := range objects {
		size = size.Max(object.MinSize())
	}
	return size
}

// domainExtractedName is the verification slice's naming rule.
var domainExtractedName = domain.ExtractedName

// isEnvelope reports a CAdES envelope whose document can be taken out.
func isEnvelope(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".p7m")
}

// extractDocument writes the document inside the envelope next to it, under
// a name that is free, and offers to open it.
func (v *verificationTab) extractDocument() {
	envelope := v.path
	output := freeName(domainExtractedName(envelope))
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		raw, err := runCommand(ctx, v.binary, []string{"extract", envelope, "--out", output, "--json"})
		fyne.Do(func() {
			v.extracted.Show()
			if err != nil {
				v.extracted.Importance = widget.DangerImportance
				v.extracted.SetText(strings.TrimSpace(raw))
				return
			}
			v.extracted.Importance = widget.SuccessImportance
			v.extracted.SetText(fmt.Sprintf(v.ui.ExtractedAs, output))
			v.open(output)
		})
	}()
}

// freeName returns path, or path with " (2)", " (3)"… before its extension
// when something is already there.
func freeName(path string) string {
	if !exists(path) {
		return path
	}
	extension := filepath.Ext(path)
	stem := strings.TrimSuffix(path, extension)
	for number := 2; ; number++ {
		candidate := fmt.Sprintf("%s (%d)%s", stem, number, extension)
		if !exists(candidate) {
			return candidate
		}
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
