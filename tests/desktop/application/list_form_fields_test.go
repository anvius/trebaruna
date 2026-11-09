package application_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

type fieldsReader struct {
	fields []domain.FormField
	err    error
}

func (r fieldsReader) EmptyFields(context.Context, string) ([]domain.FormField, error) {
	return r.fields, r.err
}

// TestTheFormsFieldsAreOfferedPageByPage: a field without a page or a box
// cannot hold a seal and is left out; an unreadable form offers none.
func TestTheFormsFieldsAreOfferedPageByPage(t *testing.T) {
	box := domain.SealRect{LowerLeftX: 10, LowerLeftY: 10, UpperRightX: 110, UpperRightY: 50}
	reader := fieldsReader{fields: []domain.FormField{
		{Name: "B", Page: 2, Rect: box}, {Name: "A", Page: 1, Rect: box},
		{Name: "no page", Rect: box}, {Name: "no box", Page: 1},
	}}
	fields := application.NewListFormFields(reader).Execute(context.Background(), "form.pdf")
	if !reflect.DeepEqual(fields, []domain.FormField{{Name: "A", Page: 1, Rect: box}, {Name: "B", Page: 2, Rect: box}}) {
		t.Errorf("%+v", fields)
	}
	if fields := application.NewListFormFields(fieldsReader{err: errors.New("not a PDF")}).Execute(context.Background(), "x"); len(fields) != 0 {
		t.Errorf("%+v", fields)
	}
}
