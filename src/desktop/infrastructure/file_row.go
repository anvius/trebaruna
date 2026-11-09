//go:build gui

package infrastructure

import (
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// fileRow shows a chosen file as a person reads it: the name, large, and the
// folder underneath, both wrapping instead of being cut. A text entry holding
// a full path showed "/home/maria/Documentos/contr…" and hid the one part
// that tells two contracts apart.
type fileRow struct {
	root   *fyne.Container
	choose *widget.Button
	hint   *widget.Label
	name   *widget.Label
	folder *widget.Label
	note   *widget.Label
	change *widget.Button
}

// newFileRow builds the row in its empty state: one clear action.
func newFileRow(chooseLabel, changeLabel, hint string, onChoose func()) *fileRow {
	row := &fileRow{
		choose: widget.NewButtonWithIcon(chooseLabel, theme.FolderOpenIcon(), onChoose),
		hint:   caption(hint),
		name:   widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		folder: caption(""),
		note:   selectableCaption(),
		change: widget.NewButton(changeLabel, onChoose),
	}
	row.name.Wrapping = fyne.TextWrapWord
	// Paths have no spaces to break at; breaking anywhere beats cutting.
	row.folder.Wrapping = fyne.TextWrapBreak
	row.root = container.NewVBox()
	row.clear()
	return row
}

// object returns the row for layout.
func (r *fileRow) object() fyne.CanvasObject { return r.root }

// clear returns to the empty state.
func (r *fileRow) clear() {
	r.root.Objects = []fyne.CanvasObject{r.choose, r.hint}
	r.root.Refresh()
}

// show displays a chosen file with an optional note underneath.
func (r *fileRow) show(path, note string) {
	r.name.SetText(filepath.Base(path))
	r.folder.SetText(filepath.Dir(path))
	r.note.SetText(note)

	// Name, folder and note read as one block, so they sit close together.
	details := container.New(layout.NewCustomPaddedVBoxLayout(0), r.name, r.folder)
	if note != "" {
		details.Add(r.note)
	}
	r.root.Objects = []fyne.CanvasObject{
		container.NewBorder(nil, nil, nil, container.NewVBox(r.change), details),
	}
	r.root.Refresh()
}

// caption is a small, quiet, wrapping line of supporting text.
func caption(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	label.SizeName = theme.SizeNameCaptionText
	label.Importance = widget.LowImportance
	return label
}

// selectableCaption is a caption the user can select and copy, for values
// such as a fingerprint that are meant to be compared elsewhere.
func selectableCaption() *widget.Label {
	label := caption("")
	label.Selectable = true
	label.Wrapping = fyne.TextWrapBreak
	return label
}
