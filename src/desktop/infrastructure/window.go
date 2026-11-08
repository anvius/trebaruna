//go:build gui

package infrastructure

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"image"
	"os"
	"strconv"
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

	"codeberg.org/simplicer/firma-it/src/desktop/application"
	"codeberg.org/simplicer/firma-it/src/desktop/domain"
	"codeberg.org/simplicer/firma-it/src/desktop/messaging"
	reportmessaging "codeberg.org/simplicer/firma-it/src/verification/messaging"
)

//go:embed assets/icons/firma-it-256.png
var appIconPNG []byte

// Window is the Fyne implementation of the desktop window.
type Window struct {
	application *application.SignFromDesktop
	preview     *application.PreviewPage
	window      fyne.Window
	messages    messaging.Catalogue
	palette     Palette

	// pageImage draws the rendered page and the seal overlay on top of it.
	pageImage  *canvas.Image
	pageHolder *fyne.Container
	overlay    *SealOverlay

	// currentPage is the page being previewed, 1-based.
	currentPage int
	// result caches the last preview so moving the seal does not re-render.
	result application.PreviewResult
	// hasPreview reports whether a document has been rendered.
	hasPreview bool
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
	fyneApp := app.NewWithID("it.firma.desktop")
	fyneApp.Settings().SetTheme(NewAppTheme(DefaultPalette()))
	fyneApp.SetIcon(fyne.NewStaticResource("firma-it.png", appIconPNG))

	catalogue := messaging.For(options.Language)

	window := fyneApp.NewWindow(catalogue.WindowTitle)
	window.Resize(fyne.NewSize(1220, 800))

	desktop := &Window{
		application: application.NewSignFromDesktop(
			application.CommandRunner{BinaryPath: options.BinaryPath},
			fileExists,
		),
		preview:     application.NewPreviewPage(NewPopplerRenderer(), application.InkFinder{}),
		binaryPath:  options.BinaryPath,
		window:      window,
		messages:    catalogue,
		palette:     DefaultPalette(),
		currentPage: 1,
	}

	// FIRMA_IT_SKIP_WELCOME opens the form directly, for the diagnostic runs and
	// for users who sign several documents a day and find the cover an obstacle.
	// Opening a document skips the cover: the user already made a choice.
	if os.Getenv("FIRMA_IT_SKIP_WELCOME") != "" || options.DocumentPath != "" {
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

	pageEntry := widget.NewEntry()
	pageEntry.SetText("1")

	boxEntry := widget.NewEntry()
	boxEntry.SetPlaceHolder("100,600,300,700")

	timestampURL := widget.NewEntry()
	timestampURL.SetPlaceHolder("https://tsa.example/tsa")

	reason := widget.NewEntry()

	statusLine := widget.NewLabel("")
	statusLine.Wrapping = fyne.TextWrapWord

	output := widget.NewMultiLineEntry()
	output.SetMinRowsVisible(6)
	output.Wrapping = fyne.TextWrapWord

	documentButton := widget.NewButtonWithIcon(m.ChooseButton, theme.FolderOpenIcon(), func() {
		pickFile(w.window, []string{".pdf"}, documentPath, func(path string) {
			w.loadPreview(documentPath, pageEntry, boxEntry, statusLine, signatureFormat)
		})
	})

	keyButton := widget.NewButtonWithIcon(m.ChooseButton, theme.FolderOpenIcon(), func() {
		pickFile(w.window, []string{".p12", ".pfx", ".pem"}, keyPath, nil)
	})

	previewButton := widget.NewButtonWithIcon(m.PreviewButton, theme.ViewFullScreenIcon(), func() {
		w.loadPreview(documentPath, pageEntry, boxEntry, statusLine, signatureFormat)
	})

	// Suggesting again re-runs the search with the current seal size, which is
	// what a user expects after noticing the proposal covers a logo.
	suggestButton := widget.NewButtonWithIcon(m.SuggestButton, theme.SearchIcon(), func() {
		w.suggestAnother(boxEntry, statusLine)
	})

	previousPage := widget.NewButtonWithIcon("", theme.NavigateBackIcon(), func() {
		w.changePage(-1, documentPath, pageEntry, boxEntry, statusLine, signatureFormat)
	})
	nextPage := widget.NewButtonWithIcon("", theme.NavigateNextIcon(), func() {
		w.changePage(+1, documentPath, pageEntry, boxEntry, statusLine, signatureFormat)
	})

	pageEntry.OnSubmitted = func(text string) {
		if parsed, err := strconv.Atoi(strings.TrimSpace(text)); err == nil && parsed > 0 {
			w.currentPage = parsed
			w.loadPreview(documentPath, pageEntry, boxEntry, statusLine, signatureFormat)
		}
	}

	var signButton *widget.Button
	signButton = widget.NewButtonWithIcon(m.SignButton, theme.ConfirmIcon(), func() {
		pageNumber, _ := strconv.Atoi(pageEntry.Text)
		if pageNumber < 1 {
			pageNumber = 1
		}

		intent := domain.SigningIntent{
			DocumentPath: documentPath.Text,
			KeyPath:      keyPath.Text,
			Passphrase:   passphrase.Text,
			Format:       signatureFormat.Selected,
			Level:        level.Selected,
			Page:         pageNumber,
			Box:          boxEntry.Text,
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
			defer signButton.Enable()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			outcome, err := w.application.Execute(ctx, intent)
			if err != nil {
				statusLine.SetText(fmt.Sprintf("%v", err))
				output.SetText(outcome.RawJSON)
				return
			}

			statusLine.SetText(m.DoneTitle)
			output.SetText(outcome.RawJSON)
			showSuccess(w.window, outcome.SignedPath, m)
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

		w.sectionTitle(m.SealSection),
		container.NewGridWithColumns(2,
			container.NewVBox(w.label(m.PageLabel), pageEntry),
			container.NewVBox(w.label(m.BoxLabel), boxEntry),
		),
		// Page navigation gets a full-width row: three items in three columns
		// pushed the "next page" arrow outside the pane.
		container.NewHBox(previousPage, nextPage),
		// No caption field: the stamp prints the certificate identity, so there
		// is nothing for the user to type inside a signature mark.
		// Stacked, not side by side: half of a 430 pt pane is not enough for
		// "Sugerir espacio" at the default font, and the label was clipped.
		// Full-width buttons also give a much larger click target.
		previewButton,
		suggestButton,

		widget.NewSeparator(),
		signButton,
		statusLine,
		widget.NewSeparator(),
		w.label(m.ResultLabel),
		output,
	)

	left := container.NewPadded(container.NewVScroll(form))
	left.Resize(fyne.NewSize(460, 780))

	// ---- right pane: the page ----
	w.pageImage = canvas.NewImageFromImage(nil)
	w.pageImage.FillMode = canvas.ImageFillContain
	w.pageImage.SetMinSize(fyne.NewSize(360, 500))

	placeholder := widget.NewLabel(m.NoPreviewYet)
	placeholder.Alignment = fyne.TextAlignCenter
	placeholder.Wrapping = fyne.TextWrapWord

	// The stack needs a definitive minimum size, otherwise the right pane starts
	// collapsed and the preview never gets room to appear. A canvas.Rectangle
	// gives the container something with an explicit size to lay out against.
	frameBackground := canvas.NewRectangle(w.palette.Surface)
	frameBackground.SetMinSize(fyne.NewSize(380, 520))
	w.pageHolder = container.NewStack(frameBackground, container.NewCenter(placeholder))

	// A plain Stack, not a Border: Border with all nil edges only centres its
	// content and never grows, which is what left the preview pane empty.
	right := container.NewStack(w.pageHolder)

	// The window is deliberately wide: a signature tool is used while reading the
	// document, so the page must always be visible next to the controls.
	split := container.NewHSplit(left, right)
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

// loadPreview renders the current page and places the seal.
func (w *Window) loadPreview(
	documentPath *widget.Entry,
	pageEntry, boxEntry *widget.Entry,
	statusLine *widget.Label,
	signatureFormat *widget.Select,
) {
	if strings.TrimSpace(documentPath.Text) == "" {
		return
	}
	if signatureFormat.Selected != "pades" {
		statusLine.SetText(w.messages.PreviewOnlyForPDF)
		return
	}

	statusLine.SetText(w.messages.RenderingMessage)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		result, err := w.preview.Execute(ctx, documentPath.Text, w.currentPage, application.DefaultSealSize())
		if err != nil {
			// A missing rasteriser is a degraded experience, not a failure: the
			// document can still be signed by typing the box coordinates.
			message := fmt.Sprintf("%v", err)
			if errors.Is(err, ErrRendererMissing) {
				message = w.messages.PreviewUnavailable
			}
			fyne.Do(func() { statusLine.SetText(message) })
			return
		}

		w.result = result
		w.hasPreview = true

		decoded, _, decodeErr := image.Decode(bytes.NewReader(result.Preview.PNG))
		if decodeErr != nil {
			statusLine.SetText(fmt.Sprintf("%v", decodeErr))
			return
		}

		// Update the widgets on the UI goroutine.
		fyne.Do(func() {
			w.pageImage.Image = decoded
			w.pageImage.Refresh()

			w.overlay = NewSealOverlay(
				result.Geometry, result.SealRect, 1.0,
				func(rect domain.SealRect) {
					boxEntry.SetText(rect.BoxString())
				},
			)

			// The image and the overlay share a stack, so the seal follows the
			// page as it scales inside the available space.
			w.pageHolder.Objects = []fyne.CanvasObject{
				container.NewStack(w.pageImage, w.overlay),
			}
			w.pageHolder.Refresh()

			boxEntry.SetText(result.SealRect.BoxString())
			pageEntry.SetText(strconv.Itoa(w.currentPage))

			statusLine.SetText(fmt.Sprintf(
				w.messages.PreviewReady, result.Preview.PageCount, w.currentPage, result.Suggestions[0].Zone,
			))
		})
	}()
}

// changePage moves to the previous or next page.
func (w *Window) changePage(
	delta int,
	documentPath *widget.Entry,
	pageEntry, boxEntry *widget.Entry,
	statusLine *widget.Label,
	signatureFormat *widget.Select,
) {
	if !w.hasPreview {
		return
	}
	target := w.currentPage + delta
	if target < 1 || target > w.result.Preview.PageCount {
		return
	}
	w.currentPage = target
	w.loadPreview(documentPath, pageEntry, boxEntry, statusLine, signatureFormat)
}

// suggestAnother asks for the next free-space proposal.
func (w *Window) suggestAnother(boxEntry *widget.Entry, statusLine *widget.Label) {
	if !w.hasPreview || w.overlay == nil {
		return
	}

	// Cycle through the suggestions already computed, then search again with the
	// same size: cheap, and the first three are usually enough.
	rects, err := w.preview.Suggest(w.result, application.DefaultSealSize())
	if err != nil || len(rects) == 0 {
		statusLine.SetText(w.messages.NoSuggestion)
		return
	}

	current := w.overlay.Rect().BoxString()
	for _, rect := range rects {
		if rect.BoxString() != current {
			w.overlay.SetRect(rect)
			boxEntry.SetText(rect.BoxString())
			statusLine.SetText(w.messages.SuggestionApplied)
			return
		}
	}

	w.overlay.SetRect(rects[0])
	boxEntry.SetText(rects[0].BoxString())
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
	}
	return err.Error()
}

// NewTestWindow builds the window content without starting the event loop, so
// diagnostics and tests can inspect the widget tree.
func NewTestWindow(options Options) fyne.Window {
	fyneApp := app.NewWithID("it.firma.desktop.diagnostics")
	fyneApp.Settings().SetTheme(NewAppTheme(DefaultPalette()))

	catalogue := messaging.For(options.Language)
	window := fyneApp.NewWindow(catalogue.WindowTitle)

	desktop := &Window{
		application: application.NewSignFromDesktop(
			application.CommandRunner{BinaryPath: options.BinaryPath},
			fileExists,
		),
		preview:     application.NewPreviewPage(NewPopplerRenderer(), application.InkFinder{}),
		binaryPath:  options.BinaryPath,
		window:      window,
		messages:    catalogue,
		palette:     DefaultPalette(),
		currentPage: 1,
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
