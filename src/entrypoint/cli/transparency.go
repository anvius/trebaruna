package cli

import (
	"fmt"
	"io"

	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// connections is the ledger of this run, never nil so JSON shows an empty
// list rather than null: "no connections" is a statement, not a gap.
func connections() []transparencydomain.Connection {
	recorded := transparency.Connections()
	if recorded == nil {
		return []transparencydomain.Connection{}
	}
	return recorded
}

// printConnections tells a person whom the command talked to.
func printConnections(writer io.Writer) {
	recorded := transparency.Connections()
	if len(recorded) == 0 {
		return
	}
	fmt.Fprintf(writer, "\nconnections (%d):\n", len(recorded))
	for _, connection := range recorded {
		outcome := fmt.Sprintf("HTTP %d", connection.Status)
		if connection.Error != "" {
			outcome = "failed: " + connection.Error
		}
		fmt.Fprintf(writer, "  %-12s %s %s  %s, %d B sent, %d B received\n",
			connection.Purpose, connection.Method, connection.URL, outcome,
			connection.SentBytes, connection.Received)
	}
}
