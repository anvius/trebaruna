//go:build gui

package infrastructure

// The requests tab is where a person approves what a web page asked for.
//
// It exists because the URI handler cannot approve itself: the secret lives in
// this window, and the page that asked has no way to read it. Everything shown
// here comes from the verification that ran before the request was queued, so the
// decision is made with the signer, the verdict and the path in front of the user.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

// pendingRequest is one request as the window reads it.
type pendingRequest struct {
	ID        string `json:"ID"`
	Path      string `json:"Path"`
	Format    string `json:"Format"`
	Territory string `json:"Territory"`
	ExpiresAt string `json:"ExpiresAt"`
}

// requestsTab renders what is waiting for a decision.
type requestsTab struct {
	window  fyne.Window
	ui      messaging.Catalogue
	palette Palette
	binary  string

	refresh  *widget.Button
	approve  *widget.Button
	reject   *widget.Button
	list     *widget.List
	detail   *widget.Label
	status   *canvas.Text
	requests []pendingRequest
	selected int
}

// newRequestsTab builds the tab.
func newRequestsTab(window fyne.Window, ui messaging.Catalogue, palette Palette, binary string) *requestsTab {
	tab := &requestsTab{
		window:   window,
		ui:       ui,
		palette:  palette,
		binary:   binary,
		detail:   widget.NewLabel(""),
		status:   canvas.NewText("", palette.TextMuted),
		selected: -1,
	}
	tab.detail.Wrapping = fyne.TextWrapWord

	tab.list = widget.NewList(
		func() int { return len(tab.requests) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(index widget.ListItemID, object fyne.CanvasObject) {
			label, ok := object.(*widget.Label)
			if !ok || index >= len(tab.requests) {
				return
			}
			request := tab.requests[index]
			label.SetText(fmt.Sprintf("%s  %s", shortID(request.ID), baseName(request.Path)))
		},
	)
	tab.list.OnSelected = func(index widget.ListItemID) {
		tab.selected = int(index)
		tab.showDetail()
	}

	tab.refresh = widget.NewButton("⟳", func() { go tab.load() })
	tab.approve = widget.NewButton(ui.Approve, func() { tab.decide(true) })
	tab.reject = widget.NewButton(ui.Reject, func() { tab.decide(false) })
	tab.approve.Importance = widget.HighImportance
	tab.approve.Disable()
	tab.reject.Disable()

	return tab
}

// content assembles the tab.
func (t *requestsTab) content() fyne.CanvasObject {
	actions := container.NewHBox(t.refresh, t.approve, t.reject)

	// The list is short by design: a request lives thirty seconds, so a long list
	// would mean something is stuck.
	split := container.NewHSplit(
		container.NewBorder(nil, nil, nil, nil, t.list),
		container.NewBorder(nil, t.status, nil, nil, t.detail),
	)
	split.Offset = 0.4

	return container.NewBorder(actions, nil, nil, nil, split)
}

// load asks the local API what is pending.
//
// It drives the CLI rather than the API directly, like the rest of the window:
// one validation path, one behaviour (ADR-0008).
func (t *requestsTab) load() {
	if t.binary == "" {
		fyne.Do(func() { t.status.Text = t.ui.NoBinary; t.status.Refresh() })
		return
	}

	output, err := runCommand(t.windowContext(), t.binary, []string{"serve", "requests"})
	if err != nil && strings.TrimSpace(output) == "" {
		fyne.Do(func() {
			t.status.Text = fmt.Sprintf("%v", err)
			t.status.Color = t.palette.Danger
			t.status.Refresh()
		})
		return
	}

	var envelope struct {
		Data []pendingRequest `json:"data"`
	}
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		fyne.Do(func() {
			t.status.Text = t.ui.VerificationUnreadable
			t.status.Refresh()
		})
		return
	}

	fyne.Do(func() {
		t.requests = envelope.Data
		t.list.Refresh()
		t.selected = -1
		t.approve.Disable()
		t.reject.Disable()
		t.detail.SetText("")

		if len(t.requests) == 0 {
			t.status.Text = t.ui.NoPendingRequests
		} else {
			t.status.Text = fmt.Sprintf(t.ui.PendingRequests, len(t.requests))
		}
		t.status.Color = t.palette.TextMuted
		t.status.Refresh()
	})
}

// showDetail renders the selected request.
func (t *requestsTab) showDetail() {
	if t.selected < 0 || t.selected >= len(t.requests) {
		t.approve.Disable()
		t.reject.Disable()
		return
	}

	request := t.requests[t.selected]
	lines := []string{
		baseName(request.Path),
		request.Path,
		request.Format,
	}
	if expires, err := time.Parse(time.RFC3339, request.ExpiresAt); err == nil {
		remaining := time.Until(expires).Truncate(time.Second)
		lines = append(lines, fmt.Sprintf("%s: %s", t.ui.ExpiresIn, remaining))
	}

	t.detail.SetText(strings.Join(lines, "\n"))
	t.approve.Enable()
	t.reject.Enable()
}

// decide sends the answer to the local API.
//
// The secret is not in the window: it is printed by the handler process and typed
// here, so a window that lists requests cannot approve one by itself either.
func (t *requestsTab) decide(approved bool) {
	if t.selected < 0 || t.selected >= len(t.requests) {
		return
	}
	request := t.requests[t.selected]

	secretEntry := widget.NewPasswordEntry()
	secretEntry.SetPlaceHolder(t.ui.ApprovalSecret)

	dialog := dialog.NewCustomConfirm(t.ui.ApprovalSecret, t.ui.Approve, t.ui.Reject,
		secretEntry, func(confirmed bool) {
			if !confirmed {
				return
			}
			go func() {
				output, err := runCommand(t.windowContext(), t.binary, []string{
					"serve", "decide", request.ID,
					"--secret", secretEntry.Text,
					fmt.Sprintf("--approved=%t", approved),
				})
				fyne.Do(func() {
					if err != nil {
						t.status.Text = strings.TrimSpace(output)
						t.status.Color = t.palette.Danger
					} else {
						t.status.Text = t.ui.DecisionRecorded
						t.status.Color = t.palette.TextMuted
					}
					t.status.Refresh()
				})
				t.load()
			}()
		}, t.window)
	dialog.Show()
}

// windowContext returns the context the command runs under.
func (t *requestsTab) windowContext() context.Context {
	return context.Background()
}

// shortID shortens an identifier for display.
func shortID(identifier string) string {
	if len(identifier) <= 8 {
		return identifier
	}
	return identifier[:8]
}

// baseName returns the last path component.
func baseName(path string) string {
	if index := strings.LastIndexAny(path, "/\\"); index >= 0 {
		return path[index+1:]
	}
	return path
}
