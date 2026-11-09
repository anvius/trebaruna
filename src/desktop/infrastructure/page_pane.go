//go:build gui

package infrastructure

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
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
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// pagePane is the right half of the signing tab: the page the seal goes on.
//
// The page is the only place the seal is chosen. There are no coordinate or
// page-number fields: the seal goes on the page being shown, where the user
// put it, and the pane says so in words.
type pagePane struct {
	messages messaging.Catalogue
	palette  Palette
	preview  *application.PreviewPage

	stage     *fyne.Container
	pageLabel *widget.Label
	previous  *namedButton
	next      *namedButton
	suggest   *widget.Button
	hint      *widget.Label
	root      fyne.CanvasObject

	canvas   *PageCanvas
	result   application.PreviewResult
	document string
	page     int
	identity SealIdentity
	// rubric widens the proposed seal and is drawn in it.
	rubric        signing.Rubric
	rubricPicture image.Image
	// run starts the render off the UI thread.
	run background
	// loading counts renders, so a slow render of a document the user has
	// already replaced does not overwrite the newer one.
	loading int
}

// newPagePane builds the pane with its empty state.
func newPagePane(messages messaging.Catalogue, palette Palette, preview *application.PreviewPage) *pagePane {
	pane := &pagePane{
		messages:  messages,
		palette:   palette,
		preview:   preview,
		pageLabel: widget.NewLabel(""),
		hint:      widget.NewLabel(""),
		page:      1,
		identity:  SealIdentity{Name: messages.SealHolderPlaceholder},
		run:       offThread,
	}
	pane.hint.Wrapping = fyne.TextWrapWord
	pane.pageLabel.Alignment = fyne.TextAlignCenter

	pane.previous = newNamedButton(messages.PreviousPage, theme.NavigateBackIcon(), func() { pane.turn(-1) })
	pane.next = newNamedButton(messages.NextPage, theme.NavigateNextIcon(), func() { pane.turn(+1) })
	pane.suggest = widget.NewButtonWithIcon(messages.SuggestButton, theme.SearchIcon(), pane.suggestAnother)

	backdrop := canvas.NewRectangle(palette.Surface)
	pane.stage = container.NewStack(backdrop)

	toolbar := container.NewHBox(pane.previous, pane.pageLabel, pane.next, layout.NewSpacer(), pane.suggest)
	pane.root = container.NewBorder(
		container.NewPadded(toolbar), container.NewPadded(pane.hint), nil, nil,
		container.NewStack(backdrop, container.NewPadded(pane.stage)),
	)
	pane.empty(messages.NoPreviewYet)
	return pane
}

// object returns the pane for the window layout.
func (p *pagePane) object() fyne.CanvasObject { return p.root }

// choice is the seal the user placed, or the signer's default without preview.
func (p *pagePane) choice() domain.SealChoice {
	if p.canvas == nil {
		return domain.SealChoice{Page: 1}
	}
	return domain.SealChoice{Page: p.page, Rect: p.canvas.Rect()}
}

// setIdentity prints the certificate holder inside the seal.
func (p *pagePane) setIdentity(identity SealIdentity) {
	if strings.TrimSpace(identity.Name) == "" {
		identity.Name = p.messages.SealHolderPlaceholder
	}
	p.identity = identity
	if p.canvas != nil {
		p.canvas.SetIdentity(identity)
	}
}

// setRubric shows the rubric in the seal and proposes a seal wide enough
// for it, as the signer's default is; a zero rubric takes it away.
func (p *pagePane) setRubric(rubric signing.Rubric, picture image.Image) {
	p.rubric, p.rubricPicture = rubric, picture
	if p.canvas != nil {
		p.render()
	}
}

// sealSize is the seal the page proposes.
func (p *pagePane) sealSize() application.SealSize {
	if p.rubric.IsZero() {
		return application.DefaultSealSize()
	}
	return application.RubricSealSize()
}

// show renders the first page of a new document.
func (p *pagePane) show(documentPath string) {
	p.document = documentPath
	p.page = 1
	p.render()
}

// withoutVisibleSeal explains why a CAdES or XAdES signature has no page.
func (p *pagePane) withoutVisibleSeal() {
	p.document = ""
	p.empty(p.messages.NoVisibleSeal)
}

// empty clears the page and states why there is nothing to place.
func (p *pagePane) empty(message string) {
	p.loading++
	p.canvas = nil

	text := widget.NewLabel(message)
	text.Wrapping = fyne.TextWrapWord
	text.Alignment = fyne.TextAlignCenter
	p.stage.Objects = []fyne.CanvasObject{container.NewCenter(container.NewGridWrap(fyne.NewSize(380, 120), text))}
	p.stage.Refresh()

	p.pageLabel.SetText("")
	p.hint.SetText("")
	p.previous.Disable()
	p.next.Disable()
	p.suggest.Disable()
}

// turn moves to the previous or next page; the seal follows the page shown.
func (p *pagePane) turn(delta int) {
	target := p.page + delta
	if p.canvas == nil || target < 1 || target > p.result.Preview.PageCount {
		return
	}
	p.page = target
	p.render()
}

// render draws the current page and proposes a free gap for the seal.
func (p *pagePane) render() {
	if strings.TrimSpace(p.document) == "" {
		return
	}
	p.loading++
	ticket, document, page, size := p.loading, p.document, p.page, p.sealSize()
	p.hint.SetText(p.messages.RenderingMessage)

	p.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		result, err := p.preview.Execute(ctx, document, page, size)
		var decoded image.Image
		if err == nil {
			decoded, _, err = image.Decode(bytes.NewReader(result.Preview.PNG))
		}

		fyne.Do(func() {
			if ticket != p.loading {
				return
			}
			if err != nil {
				p.failed(err)
				return
			}
			p.present(result, decoded)
		})
	})
}

// failed degrades to the signer's default corner: a missing renderer must
// never stop a signature.
func (p *pagePane) failed(err error) {
	message := fmt.Sprintf("%v", err)
	if errors.Is(err, ErrRendererMissing) {
		message = p.messages.PreviewUnavailable
	}
	p.empty(message)
}

// present swaps in the rendered page with the proposed seal.
func (p *pagePane) present(result application.PreviewResult, page image.Image) {
	p.result = result
	p.canvas = NewPageCanvas(result.Geometry, result.Preview.Ink, page, result.SealRect, p.identity, func(domain.SealRect) {
		p.describe()
	})
	p.canvas.SetRubric(p.rubric, p.rubricPicture)
	p.stage.Objects = []fyne.CanvasObject{p.canvas}
	p.stage.Refresh()

	p.pageLabel.SetText(fmt.Sprintf(p.messages.PageOf, p.page, result.Preview.PageCount))
	p.previous.Enable()
	p.next.Enable()
	if p.page <= 1 {
		p.previous.Disable()
	}
	if p.page >= result.Preview.PageCount {
		p.next.Disable()
	}
	p.suggest.Enable()
	p.describe()
}

// describe tells the user how to move the seal, or that it covers text.
func (p *pagePane) describe() {
	if p.canvas == nil {
		return
	}
	importance, text := widget.MediumImportance, p.messages.SealHint
	switch {
	case p.canvas.CoversText():
		importance, text = widget.WarningImportance, p.messages.SealCoversText
	case p.result.Preview.Approximate:
		text += " " + p.messages.PreviewApproximate
	}
	p.hint.Importance = importance
	p.hint.SetText(text)
	// The page says to a screen reader what the line under it says.
	p.canvas.SetDescription(text)
}

// suggestAnother cycles through the free gaps the page offers.
func (p *pagePane) suggestAnother() {
	if p.canvas == nil {
		return
	}
	size := application.SealSize{Width: p.canvas.Rect().Width(), Height: p.canvas.Rect().Height()}
	rects, err := p.preview.Suggest(p.result, size)
	if err != nil || len(rects) == 0 {
		p.hint.Importance = widget.WarningImportance
		p.hint.SetText(p.messages.NoSuggestion)
		return
	}

	current := p.canvas.Rect().BoxString()
	next := rects[0]
	for index, rect := range rects {
		if rect.BoxString() == current {
			next = rects[(index+1)%len(rects)]
			break
		}
	}
	p.canvas.SetRect(next)
}
