//go:build gui

package infrastructure

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
	transparencyinfra "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
	reportmessaging "codeberg.org/simplicer/trebaruna/src/verification/messaging"
)

//go:embed assets/icons/trebaruna-256.png
var appIconPNG []byte

// Window is the Fyne implementation of the desktop window.
type Window struct {
	application *application.SignFromDesktop
	inspect     *application.InspectCertificate
	cards       *application.ListCards
	firefox     *application.ListCards
	pinChange   *application.ChangeCardPIN
	preview     *application.PreviewPage
	window      fyne.Window
	messages    messaging.Catalogue
	palette     Palette

	// form and pages are the two halves of the signing tab.
	form  *signForm
	pages *pagePane

	// activity collects the connections every command reported.
	activity *networkActivity

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
		cards:       application.NewListCards(CommandLineCardReader{BinaryPath: binaryPath}),
		firefox:     application.NewListCards(CommandLineCardReader{BinaryPath: binaryPath, Store: domain.StoreFirefox}),
		pinChange:   application.NewChangeCardPIN(CommandLinePINChanger{BinaryPath: binaryPath}),
		preview:     application.NewPreviewPage(NewPopplerRenderer(), application.InkFinder{}),
		binaryPath:  binaryPath,
		window:      window,
		messages:    catalogue,
		palette:     DefaultPalette(),
		activity:    &networkActivity{},
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
		w.application, w.inspect, w.cards, w.firefox, w.pages)
	w.form.onNetwork = w.activity.add
	if initialDocument != "" {
		w.form.setDocument(initialDocument)
	}

	split := container.NewHSplit(w.form.object(), w.pages.object())
	// Without an explicit offset Fyne gives the left pane its minimum width.
	split.SetOffset(0.38)
	return split
}

// withTabs wraps the signing form and the verification panel in tabs, and
// installs what reaches both: the menu and the drop target.
//
// Two tabs, not two windows: a user who has just signed something usually wants
// to check it, and making that a separate launch breaks the flow. Web-page
// requests are not a tab: they are rare, they arrive from a browser, and a
// third tab that is empty almost always only adds noise. They live in the menu.
func (w *Window) withTabs(signingContent fyne.CanvasObject) fyne.CanvasObject {
	report := reportmessaging.For(languageCode(w.messages.Language))
	verification := newVerificationTab(w.window, w.messages, report, w.palette, w.binaryPath)
	verification.onNetwork = w.activity.add

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon(w.messages.SignTab, theme.DocumentCreateIcon(), signingContent),
		container.NewTabItemWithIcon(w.messages.VerifyTab, theme.SearchIcon(), verification.content()),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	checkFile := func(path string) {
		tabs.SelectIndex(1)
		verification.verifyFile(path)
	}
	if w.form != nil {
		w.form.onCheck = checkFile
	}

	w.window.SetMainMenu(w.mainMenu(tabs, checkFile))
	w.window.SetOnDropped(func(_ fyne.Position, items []fyne.URI) {
		if len(items) == 0 || w.form == nil {
			return
		}
		if len(items) > 1 && tabs.SelectedIndex() == 0 {
			paths := make([]string, 0, len(items))
			for _, item := range items {
				if !isCertificateFile(item.Path()) {
					paths = append(paths, item.Path())
				}
			}
			if len(paths) > 0 {
				w.form.setDocuments(paths)
				return
			}
		}
		w.dropped(items[0].Path(), tabs.SelectedIndex() == 1, checkFile)
	})
	return tabs
}

// dropped routes a file dropped on the window: a certificate goes to step 2,
// anything on the verification tab is checked, anything else is signed.
func (w *Window) dropped(path string, verifying bool, checkFile func(string)) {
	switch {
	case isCertificateFile(path):
		w.form.setCertificate(path)
	case verifying:
		checkFile(path)
	default:
		w.form.setDocument(path)
	}
}

// documentsIn lists the files of a folder worth signing: not hidden, not a
// key bundle, and not something this program already produced.
func documentsIn(folder string) []string {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return nil
	}
	var documents []string
	for _, entry := range entries {
		name := entry.Name()
		lower := strings.ToLower(name)
		switch {
		case entry.IsDir(), strings.HasPrefix(name, "."), isCertificateFile(name),
			strings.HasSuffix(lower, ".p7m"), strings.HasSuffix(lower, ".p7s"),
			strings.Contains(lower, "_signed."):
			continue
		}
		documents = append(documents, filepath.Join(folder, name))
	}
	return documents
}

// isCertificateFile recognises a key bundle by its suffix.
func isCertificateFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".p12", ".pfx", ".pem":
		return true
	}
	return false
}

// mainMenu lists every action once, with its shortcut, so the window can be
// driven from the keyboard and a user can find what a button does by name.
func (w *Window) mainMenu(tabs *container.AppTabs, checkFile func(string)) *fyne.MainMenu {
	m := w.messages
	control := fyne.KeyModifierShortcutDefault

	openDocument := fyne.NewMenuItem(m.MenuOpenDocument, func() {
		tabs.SelectIndex(0)
		w.form.pickDocument()
	})
	openDocument.Shortcut = &desktop.CustomShortcut{KeyName: fyne.KeyO, Modifier: control}

	signFolder := fyne.NewMenuItem(m.MenuSignFolder, func() {
		tabs.SelectIndex(0)
		dialog.ShowFolderOpen(func(folder fyne.ListableURI, err error) {
			if err != nil || folder == nil {
				return
			}
			if documents := documentsIn(folder.Path()); len(documents) > 0 {
				w.form.setDocuments(documents)
			}
		}, w.window)
	})

	chooseCertificate := fyne.NewMenuItem(m.MenuChooseCertificate, func() {
		tabs.SelectIndex(0)
		w.form.pickCertificate()
	})
	chooseCertificate.Shortcut = &desktop.CustomShortcut{KeyName: fyne.KeyK, Modifier: control}

	checkDocument := fyne.NewMenuItem(m.MenuCheckDocument, func() {
		newFileOpen(w.window, signedExtensions, checkFile).Show()
	})
	checkDocument.Shortcut = &desktop.CustomShortcut{KeyName: fyne.KeyO, Modifier: control | fyne.KeyModifierShift}

	sign := fyne.NewMenuItem(m.SignButton, func() {
		tabs.SelectIndex(0)
		w.form.sign()
	})
	sign.Shortcut = &desktop.CustomShortcut{KeyName: fyne.KeyReturn, Modifier: control}

	previous := fyne.NewMenuItem(m.MenuPreviousPage, func() { w.pages.turn(-1) })
	previous.Shortcut = &desktop.CustomShortcut{KeyName: fyne.KeyPageUp, Modifier: control}
	next := fyne.NewMenuItem(m.MenuNextPage, func() { w.pages.turn(+1) })
	next.Shortcut = &desktop.CustomShortcut{KeyName: fyne.KeyPageDown, Modifier: control}
	freeSpace := fyne.NewMenuItem(m.SuggestButton, w.pages.suggestAnother)
	freeSpace.Shortcut = &desktop.CustomShortcut{KeyName: fyne.KeyF, Modifier: control}

	return fyne.NewMainMenu(
		fyne.NewMenu(m.MenuFile, openDocument, signFolder, chooseCertificate, fyne.NewMenuItemSeparator(), checkDocument),
		fyne.NewMenu(m.MenuSignature, sign, fyne.NewMenuItemSeparator(), previous, next, freeSpace),
		fyne.NewMenu(m.MenuCard,
			fyne.NewMenuItem(m.MenuChangePIN, func() { w.showPINDialog(domain.ChangePIN) }),
			fyne.NewMenuItem(m.MenuUnlockPIN, func() { w.showPINDialog(domain.UnlockPIN) }),
		),
		fyne.NewMenu(m.MenuTools,
			fyne.NewMenuItem(m.MenuNetwork, w.showNetworkActivity),
			fyne.NewMenuItem(m.MenuRequests, w.showRequests),
		),
		fyne.NewMenu(m.MenuHelp,
			fyne.NewMenuItem(m.MenuManual, func() { _ = fyne.CurrentApp().OpenURL(manualURL()) }),
			fyne.NewMenuItem(m.MenuAbout, w.showAbout),
		),
	)
}

// showRequests opens the web-page requests in their own window.
func (w *Window) showRequests() {
	requests := newRequestsTab(w.window, w.messages, w.palette, w.binaryPath)
	window := fyne.CurrentApp().NewWindow(w.messages.RequestsTab)
	requests.window = window
	window.SetContent(requests.content())
	window.Resize(fyne.NewSize(760, 440))
	window.Show()
	go requests.load()
}

// showNetworkActivity lists every connection made during the session.
func (w *Window) showNetworkActivity() {
	window := fyne.CurrentApp().NewWindow(w.messages.NetworkTitle)
	window.SetContent(activityContent(w.activity.list(), w.messages))
	window.Resize(fyne.NewSize(720, 460))
	window.Show()
}

// showAbout states what the program is, which build it is, and every
// dependency linked into it with its licence (`trebaruna about --json`).
func (w *Window) showAbout() {
	m := w.messages
	build, err := w.describeBuild()
	version := m.UnknownVersion
	if err == nil {
		version = build.Version
	}

	text := widget.NewLabel(fmt.Sprintf(m.AboutText, version))
	text.Wrapping = fyne.TextWrapWord
	source := widget.NewHyperlink(sourceURL().String(), sourceURL())
	logo := canvas.NewImageFromImage(decodeIcon())
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(96, 96))
	content := container.NewVBox(logo, text, source)

	if err == nil {
		cards := m.AboutCardsNo
		if build.PKCS11 {
			cards = m.AboutCardsYes
		}
		details := []string{build.Platform + ", " + build.Go, cards}
		if build.Revision != "" {
			details = append(details, fmt.Sprintf(m.AboutRevision, build.Revision))
		}
		content.Add(caption(strings.Join(details, "\n")))

		var listing strings.Builder
		for _, dependency := range build.Dependencies {
			fmt.Fprintf(&listing, "%s %s — %s\n", dependency.Path, dependency.Version, dependency.License)
		}
		dependencies := selectableCaption()
		dependencies.SetText(strings.TrimSpace(listing.String()))
		content.Add(widget.NewAccordion(widget.NewAccordionItem(
			fmt.Sprintf(m.AboutDependencies, len(build.Dependencies)),
			container.NewVScroll(dependencies))))
	}

	about := dialog.NewCustom(m.MenuAbout, m.CloseButton, content, w.window)
	about.Resize(fyne.NewSize(560, 520))
	about.Show()
}

// describeBuild asks the command what it is.
func (w *Window) describeBuild() (transparencyinfra.Build, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := runCommand(ctx, w.binaryPath, []string{"about", "--json"})
	if err != nil {
		return transparencyinfra.Build{}, err
	}
	var build transparencyinfra.Build
	if err := json.Unmarshal([]byte(output), &build); err != nil {
		return transparencyinfra.Build{}, err
	}
	return build, nil
}

func sourceURL() *url.URL {
	parsed, _ := url.Parse("https://codeberg.org/simplicer/trebaruna")
	return parsed
}

func manualURL() *url.URL {
	parsed, _ := url.Parse("https://codeberg.org/simplicer/trebaruna/src/branch/main/docs/desktop.md")
	return parsed
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
	case domain.ProblemMissingPIN:
		return m.MissingPIN
	case domain.ProblemCardLocked:
		return m.CardLocked
	case domain.ProblemPINExpired:
		return m.PINExpired
	case domain.ProblemWrongPIN:
		switch problem.Detail {
		case string(signing.PINFinalTry):
			return m.WrongPINFinalTry
		case string(signing.PINLocked):
			return m.WrongPINNowLocked
		}
		return m.WrongPIN
	case domain.ProblemMissingSaveTo:
		return m.MissingSaveTo
	case domain.ProblemMissingPUK:
		return m.MissingPUK
	case domain.ProblemPUKLocked:
		return m.PUKLocked
	case domain.ProblemPINMismatch:
		return m.PINMismatch
	case domain.ProblemWrongPUK:
		switch problem.Detail {
		case string(signing.PINFinalTry):
			return m.WrongPUKFinalTry
		case string(signing.PINLocked):
			return m.WrongPUKNowLocked
		}
		return m.WrongPUK
	case domain.ProblemNewPINRejected:
		kind, limit, _ := strings.Cut(problem.Detail, ":")
		switch kind {
		case "min":
			return fmt.Sprintf(m.NewPINTooShort, limit)
		case "max":
			return fmt.Sprintf(m.NewPINTooLong, limit)
		}
		return m.NewPINRejected
	}
	return err.Error()
}
