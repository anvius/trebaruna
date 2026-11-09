package infrastructure

// No build tag: plain os/exec, tested by `make test` with a stand-in command.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// CommandLineFormFields lists a PDF form's empty signature fields by
// running `trebaruna fields --json`: the window offers the fields the
// command signs in.
type CommandLineFormFields struct {
	BinaryPath string
}

// EmptyFields runs the command for one document.
func (r CommandLineFormFields) EmptyFields(ctx context.Context, documentPath string) ([]domain.FormField, error) {
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, r.BinaryPath, "fields", documentPath, "--json")
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, errors.New(meaningfulLine(stderr.String(), stdout.String(), err))
	}
	var printed struct {
		Fields []struct {
			Name string     `json:"name"`
			Page int        `json:"page"`
			Box  [4]float64 `json:"box"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		return nil, fmt.Errorf("the fields command printed an unreadable answer: %w", err)
	}
	fields := make([]domain.FormField, 0, len(printed.Fields))
	for _, field := range printed.Fields {
		fields = append(fields, domain.FormField{Name: field.Name, Page: field.Page, Rect: domain.SealRect{
			LowerLeftX: min(field.Box[0], field.Box[2]), LowerLeftY: min(field.Box[1], field.Box[3]),
			UpperRightX: max(field.Box[0], field.Box[2]), UpperRightY: max(field.Box[1], field.Box[3]),
		}})
	}
	return fields, nil
}

// compile-time check.
var _ application.FormFieldReader = CommandLineFormFields{}
