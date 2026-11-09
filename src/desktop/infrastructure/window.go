//go:build gui

package infrastructure

import (
	_ "embed"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	reportmessaging "codeberg.org/simplicer/trebaruna/src/verification/messaging"
)

//go:embed assets/icons/trebaruna-256.png
var appIconPNG []byte

// Window is the Fyne implementation of the desktop window.
type Window struct {
	application *application.SignFromDesktop
	inspect     *application.InspectCertificate
	preview     *application.PreviewPage
	window      fyne.Window
	messages    messaging.Catalogue
	palette     Palette

	// form and pages are the two halves of the signing tab.
	form  *signForm
	pages *pagePane

	// binaryPath is the CLI the window drives.
	binaryPath string
}

// Options configures the window.
type Options struct {
	BinaryPath string
	Language   messaging.Language
	// DocumentPath is the file passed on the command line, when the user opened
	// the app from a file manager.
	DocumentPath string
}

// NewWindow builds the window and returns it ready to run.
func NewWindow(options Options) *Window {
	fyneApp := app.NewWithID("org.codeberg.simplicer.trebaruna")
	fyneApp.Settings().SetTheme(NewAppTheme(DefaultPalette()))
	fyneApp.SetIcon(fyne.NewStaticResource("trebaruna.png", appIconPNG))

	catalogue := messaging.For(options.Language)

	window := fyneApp.NewWindow(catalogue.WindowTitle)
	window.Resize(fyne.NewSize(1220, 800))

	desktop := newDesktop(window, catalogue, options.BinaryPath)

	// TREBARUNA_SKIP_WELCOME opens the form directly, for the diagnostic runs and
	// for users who sign several documents a day and find the cover an obstacle.
	// Opening a document skips the cover: the user already made a choice.
	if os.Getenv("TREBARUNA_SKIP_WELCOME") != "" || options.DocumentPath != "" {
		window.SetContent(desktop.withTabs(desktop.buildContent(options.DocumentPath)))
		return desktop
	}

	// Otherwise the cover is set first and the form is built on demand: building
	// it eagerly costs a render pass on a window the user may never reach.
	welcome := NewWelcomeScreen(window, desktop.palette, catalogue, func() {
		window.SetContent(desktop.withTabs(desktop.buildContent("")))
	})
	window.SetContent(welcome.CanvasObject())

	return desktop
}

// newDesktop wires the use cases to their command-line adapters.
func newDesktop(window fyne.Window, catalogue messaging.Catalogue, binaryPath string) *Window {
	return &Window{
		application: application.NewSignFromDesktop(CommandLineSigner{BinaryPath: binaryPath}, fileExists),
		inspect:     application.NewInspectCertificate(CommandLineCertificateReader{BinaryPath: binaryPath}),
		preview:     application.NewPreviewPage(NewPopplerRenderer(), application.InkFinder{}),
		binaryPath:  binaryPath,
		window:      window,
		messages:    catalogue,
		palette:     DefaultPalette(),
	}
}

// Run shows the window and blocks until it closes.
func (w *Window) Run() {
	w.window.ShowAndRun()
}

// buildContent lays out the signing tab: the steps on the left, the page on
// the right. The window is wide on purpose: a signature is placed while
// reading the document, so the page must stay visible next to the controls.
func (w *Window) buildContent(initialDocument string) fyne.CanvasObject {
	w.pages = newPagePane(w.messages, w.palette, w.preview)
	w.form = newSignForm(w.window, w.messages, w.palette, fyne.CurrentApp().Preferences(),
		w.application, w.inspect, w.pages)
	if initialDocument != "" {
		w.form.setDocument(initialDocument)
	}

	split := container.NewHSplit(w.form.object(), w.pages.object())
	// Without an explicit offset Fyne gives the left pane its minimum width.
	split.SetOffset(0.38)
	return split
}

// withTabs wraps the signing form and the verification panel in tabs.
//
// Two tabs, not two windows: a user who has just signed something usually wants
// to check it, and making that a separate launch breaks the flow.
func (w *Window) withTabs(signingContent fyne.CanvasObject) fyne.CanvasObject {
	report := reportmessaging.For(languageCode(w.messages.Language))
	verification := newVerificationTab(w.window, w.messages, report, w.palette, w.binaryPath)
	requests := newRequestsTab(w.window, w.messages, w.palette, w.binaryPath)

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon(w.messages.SignTab, theme.DocumentCreateIcon(), signingContent),
		container.NewTabItemWithIcon(w.messages.VerifyTab, theme.SearchIcon(), verification.content()),
		container.NewTabItemWithIcon(w.messages.RequestsTab, theme.MailComposeIcon(), requests.content()),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	if w.form != nil {
		w.form.onCheck = func(path string) {
			tabs.SelectIndex(1)
			verification.check(path)
		}
	}
	return tabs
}

// newFileOpen builds a file dialog, filtered when extensions are given.
func newFileOpen(parent fyne.Window, extensions []string, chosen func(string)) *dialog.FileDialog {
	picker := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil || reader == nil {
			return
		}
		path := reader.URI().Path()
		_ = reader.Close()
		chosen(path)
	}, parent)
	if len(extensions) > 0 {
		picker.SetFilter(storage.NewExtensionFileFilter(extensions))
	}
	picker.Resize(fyne.NewSize(900, 600))
	return picker
}

// openWithSystemViewer delegates to the desktop portal.
func openWithSystemViewer(path string) {
	for _, candidate := range [][]string{
		{"xdg-open", path},
		{"open", path},
		{"rundll32", "url.dll,FileProtocolHandler", path},
	} {
		if _, err := lookPath(candidate[0]); err != nil {
			continue
		}
		_ = startDetached(candidate[0], candidate[1:])
		return
	}
}

// translate renders a validation problem in the active language.
func translate(err error, m messaging.Catalogue) string {
	problem, ok := err.(domain.Problem)
	if !ok {
		return err.Error()
	}

	switch problem.Code {
	case domain.ProblemMissingDocument:
		return m.MissingDocument
	case domain.ProblemMissingKey:
		return m.MissingKey
	case domain.ProblemMissingTSA:
		return m.MissingTSAMessage(problem.Detail)
	case domain.ProblemInvalidPage:
		return m.InvalidPage
	case domain.ProblemNoOutput:
		return m.NoOutputMessage(problem.Detail)
	case domain.ProblemLockedCertificate:
		return m.CertificateLocked
	}
	return err.Error()
}
