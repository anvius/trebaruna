package application

import (
	"context"
	"slices"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// FormFieldReader lists the empty signature fields of a PDF form.
type FormFieldReader interface {
	EmptyFields(ctx context.Context, documentPath string) ([]domain.FormField, error)
}

// ListFormFields is the use case behind the form's field choice: the boxes
// a PDF form reserves for its signatures, which the person may sign in
// instead of placing the seal.
type ListFormFields struct {
	reader FormFieldReader
}

// NewListFormFields wires the use case.
func NewListFormFields(reader FormFieldReader) *ListFormFields {
	return &ListFormFields{reader: reader}
}

// Execute lists the fields, page by page: a document that cannot be read
// as a form has none to offer, which is not an error for the window.
func (u *ListFormFields) Execute(ctx context.Context, documentPath string) []domain.FormField {
	fields, err := u.reader.EmptyFields(ctx, documentPath)
	if err != nil {
		return nil
	}
	ordered := make([]domain.FormField, 0, len(fields))
	for _, field := range fields {
		if field.Page >= 1 && field.Rect.Width() > 0 && field.Rect.Height() > 0 {
			ordered = append(ordered, field)
		}
	}
	slices.SortStableFunc(ordered, func(a, b domain.FormField) int { return a.Page - b.Page })
	return ordered
}
