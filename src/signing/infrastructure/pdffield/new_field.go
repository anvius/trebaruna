package pdffield

import (
	"fmt"
	"strings"

	"github.com/digitorus/pdf"
)

// Widget is one mark of a new signature field: its page, from 1, its box,
// and what it shows. A signature without a mark has one widget with an
// empty box and no appearance.
type Widget struct {
	Page       int
	Rect       [4]float64
	Appearance *Appearance
}

// SignNew signs the document in a new signature field, "Signature n",
// shown by the widgets given (one empty widget on the first page when
// none): what the PDF library does, written here when its signature needs
// what the library cannot add, such as a signature policy.
func SignNew(content []byte, widgets []Widget, signature Signature) ([]byte, error) {
	reader, err := openForSigning(content)
	if err != nil {
		return nil, err
	}
	if len(widgets) == 0 {
		widgets = []Widget{{Page: 1}}
	}
	update, err := newUpdate(content, reader)
	if err != nil {
		return nil, err
	}
	fieldID, signatureID := update.allocate(), update.allocate()
	name := fmt.Sprintf("Signature %d", len(signatureFieldNames(reader))+1)

	widgetIDs := make([]uint32, len(widgets))
	annotations := map[int][]string{}
	for index, widget := range widgets {
		if widget.Page < 1 || widget.Page > reader.NumPage() {
			return nil, fmt.Errorf("page %d is not in the document (%d pages)", widget.Page, reader.NumPage())
		}
		widgetIDs[index] = fieldID
		if len(widgets) > 1 {
			widgetIDs[index] = update.allocate()
		}
		annotations[widget.Page] = append(annotations[widget.Page], fmt.Sprintf("%d 0 R", widgetIDs[index]))
	}

	var kids []string
	for index, widget := range widgets {
		page := reader.Page(widget.Page).V
		entries := fmt.Sprintf("/Type /Annot /Subtype /Widget /Rect [%s %s %s %s] /P %s /F 4",
			number(widget.Rect[0]), number(widget.Rect[1]), number(widget.Rect[2]), number(widget.Rect[3]), reference(page))
		if widget.Appearance != nil {
			formID := update.writeAppearance(abs(widget.Rect[2]-widget.Rect[0]), abs(widget.Rect[3]-widget.Rect[1]), widget.Appearance)
			entries += fmt.Sprintf(" /AP << /N %d 0 R >>", formID)
		}
		if len(widgets) == 1 {
			update.write(fieldID, fmt.Sprintf("<< /FT /Sig /T %s /V %d 0 R %s >>", pdfString(name), signatureID, entries), nil)
			continue
		}
		update.write(widgetIDs[index], fmt.Sprintf("<< %s /Parent %d 0 R >>", entries, fieldID), nil)
		kids = append(kids, fmt.Sprintf("%d 0 R", widgetIDs[index]))
	}
	if len(widgets) > 1 {
		update.write(fieldID, fmt.Sprintf("<< /FT /Sig /T %s /V %d 0 R /Kids [%s] >>", pdfString(name), signatureID, strings.Join(kids, " ")), nil)
	}

	for number, references := range annotations {
		if err := update.annotate(reader.Page(number).V, references); err != nil {
			return nil, err
		}
	}
	if err := update.addField(reader, fmt.Sprintf("%d 0 R", fieldID)); err != nil {
		return nil, err
	}
	update.signaturePlaceholder(signatureID, signature)
	return update.finish(signatureID, signature)
}

// signatureFieldNames are the names of the document's fields, to number a
// new one after them.
func signatureFieldNames(reader *pdf.Reader) []string {
	var names []string
	var visit func(fields pdf.Value, depth int)
	visit = func(fields pdf.Value, depth int) {
		for index := 0; index < fields.Len() && depth < 16; index++ {
			field := fields.Index(index)
			if field.Key("FT").Name() == "Sig" {
				names = append(names, field.Key("T").Text())
			}
			visit(field.Key("Kids"), depth+1)
		}
	}
	visit(reader.Trailer().Key("Root").Key("AcroForm").Key("Fields"), 0)
	return names
}

// annotate adds widgets to a page's /Annots: the page written again, or
// its annotations array when that is an object of its own.
func (u *update) annotate(page pdf.Value, widgets []string) error {
	annotations := page.Key("Annots")
	if !annotations.IsNull() && annotations.GetPtr() != page.GetPtr() {
		return u.rewriteArray(annotations, widgets)
	}
	return u.rewrite(page, map[string]string{"Annots": arrayWith(annotations, widgets)})
}

// addField adds a field to the form, and the form to the catalogue when it
// has none, with /SigFlags 3.
func (u *update) addField(reader *pdf.Reader, field string) error {
	root := reader.Trailer().Key("Root")
	form := root.Key("AcroForm")
	switch {
	case form.IsNull():
		return u.rewrite(root, map[string]string{"AcroForm": fmt.Sprintf("<< /Fields [%s] /SigFlags 3 >>", field)})
	case form.GetPtr() != root.GetPtr():
		return u.rewrite(form, map[string]string{"Fields": arrayWith(form.Key("Fields"), []string{field}), "SigFlags": "3"})
	}
	return u.rewrite(root, map[string]string{"AcroForm": dictionaryWith(form, map[string]string{
		"Fields": arrayWith(form.Key("Fields"), []string{field}), "SigFlags": "3"})})
}

// rewriteArray writes an array object again with elements added.
func (u *update) rewriteArray(array pdf.Value, extra []string) error {
	pointer := array.GetPtr()
	if pointer.GetID() == 0 || array.Kind() != pdf.Array {
		return fmt.Errorf("%w: an annotations array that is not an array", ErrUnsupported)
	}
	u.writeWithGeneration(pointer.GetID(), int(pointer.GetGen()), arrayWith(array, extra), nil)
	return nil
}

// arrayWith writes an array, elements added; a missing array is just the
// elements.
func arrayWith(array pdf.Value, extra []string) string {
	var parts []string
	for index := 0; index < array.Len(); index++ {
		parts = append(parts, serialize(array, array.Index(index), 1))
	}
	return "[" + strings.Join(append(parts, extra...), " ") + "]"
}
