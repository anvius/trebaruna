//go:build gui

package infrastructure

import (
	"fmt"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
)

// networkActivity is every connection the commands reported during this
// session. The window never opens a connection itself (ADR-0008); it collects
// what each signature and each check says it did, so the user can see all of
// it in one place (ADR-0010).
type networkActivity struct {
	mu      sync.Mutex
	entries []transparency.Connection
}

func (a *networkActivity) add(connections []transparency.Connection) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, connections...)
}

func (a *networkActivity) list() []transparency.Connection {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]transparency.Connection{}, a.entries...)
}

// summarise names the destinations of a set of connections in one line, for
// the status under the Sign button.
func summarise(connections []transparency.Connection, m messaging.Catalogue) string {
	if len(connections) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var parts []string
	for _, connection := range connections {
		part := fmt.Sprintf("%s (%s)", connection.Host(), purposeName(connection.Purpose, m))
		if !seen[part] {
			seen[part] = true
			parts = append(parts, part)
		}
	}
	return fmt.Sprintf(m.NetworkSummary, strings.Join(parts, ", "))
}

// purposeName says why a connection was made, in the user's language.
func purposeName(purpose transparency.Purpose, m messaging.Catalogue) string {
	switch purpose {
	case transparency.PurposeTimestamp:
		return m.PurposeTimestamp
	case transparency.PurposeRevocation:
		return m.PurposeRevocation
	case transparency.PurposeTrustList:
		return m.PurposeTrustList
	case transparency.PurposeWebDelivery:
		return m.PurposeWebDelivery
	case transparency.PurposeLocalAPI:
		return m.PurposeLocalAPI
	case transparency.PurposeSigningServer:
		return m.PurposeSigningServer
	case transparency.PurposeRemoteSigning:
		return m.PurposeRemoteSigning
	}
	return m.PurposeUnattributed
}

// activityContent lists the session's connections, newest first.
func activityContent(entries []transparency.Connection, m messaging.Catalogue) fyne.CanvasObject {
	if len(entries) == 0 {
		empty := widget.NewLabel(m.NetworkEmpty)
		empty.Wrapping = fyne.TextWrapWord
		return container.NewPadded(empty)
	}

	rows := container.NewVBox()
	for index := len(entries) - 1; index >= 0; index-- {
		connection := entries[index]
		title := widget.NewLabelWithStyle(
			fmt.Sprintf("%s: %s", purposeName(connection.Purpose, m), connection.Host()),
			fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		title.Wrapping = fyne.TextWrapWord

		outcome := fmt.Sprintf("HTTP %d", connection.Status)
		if connection.Error != "" {
			outcome = connection.Error
		}
		details := []string{
			connection.Method + " " + connection.URL,
			outcome + ", " + fmt.Sprintf(m.NetworkBytes, readableSize(connection.SentBytes), readableSize(connection.Received)),
			connection.StartedAt.Local().Format("02/01/2006 15:04:05"),
		}
		if connection.Via == "library" {
			details = append(details, m.NetworkViaLibrary)
		}
		line := caption(strings.Join(details, "\n"))
		line.Wrapping = fyne.TextWrapBreak
		rows.Add(container.NewVBox(widget.NewSeparator(), title, line))
	}
	return container.NewVScroll(container.NewPadded(rows))
}

func readableSize(bytes int64) string {
	switch {
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(bytes)/(1<<10))
	}
	return fmt.Sprintf("%d B", bytes)
}
