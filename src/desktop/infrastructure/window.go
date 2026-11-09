//go:build gui

package infrastructure

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

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
	preview     *application.PreviewPage
	window      fyne.Window
	messages    messaging.Catalogue
	palette     Palette

	// pages is the right pane, where the seal is placed.
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

	desktop := &Window{
		application: application.NewSignFromDesktop(
			CommandLineSigner{BinaryPath: options.BinaryPath},
			fileExists,
		),
		preview:    application.NewPreviewPage(NewPopplerRenderer(), application.InkFinder{}),
		binaryPath: options.BinaryPath,
		window:     window,
		messages:   catalogue,
		palette:    DefaultPalette(),
	}

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

// Run shows the window and blocks until it closes.
func (w *Window) Run() {
	w.window.ShowAndRun()
}

// DebugContent reports the shape of the widget tree, for the diagnostic command.
func DebugContent(content fyne.CanvasObject) string {
	var builder strings.Builder
	var visit func(fyne.CanvasObject, int)
	visit = func(object fyne.CanvasObject, depth int) {
		builder.WriteString(strings.Repeat("  ", depth))
		builder.WriteString(fmt.Sprintf("%T min=%v\n", object, object.MinSize()))
		if containerObject, ok := object.(*fyne.Container); ok {
			for _, child := range containerObject.Objects {
				visit(child, depth+1)
			}
			return
		}
		if widgetObject, ok := object.(fyne.Widget); ok {
			if renderer := widgetObject.CreateRenderer(); renderer != nil {
				for _, child := range renderer.Objects() {
					visit(child, depth+1)
				}
			}
		}
	}
	visit(content, 0)
	return builder.String()
}

// buildContent lays out the two-pane window: form on the left, page on the right.
func (w *Window) buildContent(initialDocument string) fyne.CanvasObject {
	m := w.messages

	documentPath := widget.NewEntry()
	documentPath.SetPlaceHolder("contratto.pdf")
	if initialDocument != "" {
		documentPath.SetText(initialDocument)
	}

	keyPath := widget.NewEntry()
	keyPath.SetPlaceHolder("mario.p12")

	passphrase := widget.NewPasswordEntry()
	passphrase.SetPlaceHolder(m.PassphraseLabel)

	signatureFormat := widget.NewSelect([]string{"pades", "cades", "xades"}, nil)
	signatureFormat.SetSelected("pades")

	level := widget.NewSelect([]string{"bes", "t"}, nil)
	level.SetSelected("bes")

	timestampURL := widget.NewEntry()
	timestampURL.SetPlaceHolder("https://tsa.example/tsa")

	reason := widget.NewEntry()

	statusLine := widget.NewLabel("")
	statusLine.Wrapping = fyne.TextWrapWord

	output := widget.NewMultiLineEntry()
	output.SetMinRowsVisible(6)
	output.Wrapping = fyne.TextWrapWord

	w.pages = newPagePane(m, w.palette, w.preview)

	// The page follows the document and the format: a PDF signed as PAdES has
	// a page to put the seal on; CAdES and XAdES carry no visible mark.
	refreshPage := func() {
		switch {
		case signatureFormat.Selected != "pades":
			w.pages.withoutVisibleSeal()
		case strings.TrimSpace(documentPath.Text) != "":
			w.pages.show(documentPath.Text)
		}
	}
	signatureFormat.OnChanged = func(string) { refreshPage() }

	documentButton := widget.NewButtonWithIcon(m.ChooseButton, theme.FolderOpenIcon(), func() {
		pickFile(w.window, []string{".pdf"}, documentPath, func(string) { refreshPage() })
	})

	keyButton := widget.NewButtonWithIcon(m.ChooseButton, theme.FolderOpenIcon(), func() {
		pickFile(w.window, []string{".p12", ".pfx", ".pem"}, keyPath, nil)
	})

	var signButton *widget.Button
	signButton = widget.NewButtonWithIcon(m.SignButton, theme.ConfirmIcon(), func() {
		intent := domain.SigningIntent{
			DocumentPath: documentPath.Text,
			KeyPath:      keyPath.Text,
			Passphrase:   passphrase.Text,
			Format:       signatureFormat.Selected,
			Level:        level.Selected,
			Seal:         w.pages.choice(),
			TimestampURL: timestampURL.Text,
			Reason:       reason.Text,
		}

		if err := intent.Validate(); err != nil {
			dialog.ShowError(fmt.Errorf("%s", translate(err, m)), w.window)
			return
		}

		signButton.Disable()
		statusLine.SetText(m.SigningMessage)

		go func() {
			defer fyne.Do(signButton.Enable)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			receipt, err := w.application.Execute(ctx, intent)
			if err != nil {
				fyne.Do(func() { statusLine.SetText(translate(err, m)) })
				return
			}

			fyne.Do(func() {
				statusLine.SetText(m.DoneTitle)
				output.SetText(receipt.SignedPath + "\n" + receipt.Standard + " · " + receipt.Signer)
				showSuccess(w.window, receipt.SignedPath, m)
			})
		}()
	})
	signButton.Importance = widget.HighImportance

	// ---- left pane: the form ----
	//
	// Buttons live in their own rows instead of being packed into a three-column
	// grid: a 430 pt pane gives each column ~140 pt, and the three seal buttons
	// plus two labels did not fit, so the last one was clipped.
	form := container.NewVBox(
		w.sectionTitle(m.DocumentSection),
		container.NewBorder(nil, nil, nil, documentButton, documentPath),
		container.NewGridWithColumns(2,
			container.NewVBox(
				container.NewBorder(nil, nil, nil, keyButton, keyPath),
			),
			container.NewVBox(passphrase),
		),

		w.sectionTitle(m.OptionsSection),
		container.NewGridWithColumns(2,
			container.NewVBox(w.label(m.FormatLabel), signatureFormat),
			container.NewVBox(w.label(m.LevelLabel), level),
		),
		w.label(m.TSALabel),
		timestampURL,
		w.label(m.ReasonLabel),
		reason,

		widget.NewSeparator(),
		signButton,
		statusLine,
		widget.NewSeparator(),
		w.label(m.ResultLabel),
		output,
	)

	left := container.NewPadded(container.NewVScroll(form))
	left.Resize(fyne.NewSize(460, 780))

	if initialDocument != "" {
		refreshPage()
	}

	// The window is deliberately wide: a signature tool is used while reading the
	// document, so the page must always be visible next to the controls.
	split := container.NewHSplit(left, w.pages.object())
	// Without an explicit offset Fyne gives the left pane its minimum width, which
	// on a wide window renders as an almost empty strip.
	split.SetOffset(0.42)
	return split
}

// sectionTitle renders a heading with the accent colour.
func (w *Window) sectionTitle(text string) fyne.CanvasObject {
	label := canvas.NewText(text, w.palette.Accent)
	label.TextSize = 15
	label.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewVBox(label, widget.NewSeparator())
}

// label renders a small field caption.
func (w *Window) label(text string) fyne.CanvasObject {
	label := canvas.NewText(text, w.palette.TextMuted)
	label.TextSize = 12
	return label
}

// pickFile opens a filtered file dialog and writes the choice into target.
func pickFile(parent fyne.Window, extensions []string, target *widget.Entry, after func(string)) {
	picker := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil || reader == nil {
			return
		}
		path := reader.URI().Path()
		_ = reader.Close()
		target.SetText(path)
		if after != nil {
			after(path)
		}
	}, parent)
	picker.SetFilter(storage.NewExtensionFileFilter(extensions))
	picker.Resize(fyne.NewSize(900, 600))
	picker.Show()
}

// showSuccess offers to open the signed file in the system viewer.
func showSuccess(parent fyne.Window, signedPath string, m messaging.Catalogue) {
	open := dialog.NewConfirm(
		m.DoneTitle,
		m.DoneMessage(signedPath),
		func(confirmed bool) {
			if confirmed {
				openWithSystemViewer(signedPath)
			}
		},
		parent,
	)
	open.Show()
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

// fileExists reports whether the path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
	}
	return err.Error()
}

// NewTestWindow builds the window content without starting the event loop, so
// diagnostics and tests can inspect the widget tree.
func NewTestWindow(options Options) fyne.Window {
	fyneApp := app.NewWithID("org.codeberg.simplicer.trebaruna.diagnostics")
	fyneApp.Settings().SetTheme(NewAppTheme(DefaultPalette()))

	catalogue := messaging.For(options.Language)
	window := fyneApp.NewWindow(catalogue.WindowTitle)

	desktop := &Window{
		application: application.NewSignFromDesktop(
			CommandLineSigner{BinaryPath: options.BinaryPath},
			fileExists,
		),
		preview:    application.NewPreviewPage(NewPopplerRenderer(), application.InkFinder{}),
		binaryPath: options.BinaryPath,
		window:     window,
		messages:   catalogue,
		palette:    DefaultPalette(),
	}
	window.SetContent(desktop.withTabs(desktop.buildContent(options.DocumentPath)))
	return window
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
	return tabs
}
