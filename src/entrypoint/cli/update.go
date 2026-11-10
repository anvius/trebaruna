package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	updatesapp "codeberg.org/simplicer/trebaruna/src/updates/application"
	updatesinfra "codeberg.org/simplicer/trebaruna/src/updates/infrastructure"
)

// updateReport is `update --json`.
type updateReport struct {
	Running     string                          `json:"running"`
	Latest      string                          `json:"latest"`
	Page        string                          `json:"page"`
	Newer       bool                            `json:"newer"`
	Connections []transparencydomain.Connection `json:"connections"`
}

// runUpdate asks where trebaruna is published whether a newer release
// exists, and says where to get it. It reaches the network only because
// the person asked, lists the connection, and downloads nothing.
func runUpdate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	from := flags.String("from", updatesinfra.ProjectRepository, "the Forgejo or Gitea repository trebaruna is published in")
	asJSON := flags.Bool("json", false, "machine-readable output")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna update [--json]")
		fmt.Fprintln(stderr, "  says whether a newer release is published, and where; downloads nothing")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	verdict, err := updatesapp.NewCheckForUpdate(updatesinfra.CodebergReleases{Repository: *from}).Execute(ctx, version)
	if err != nil {
		fmt.Fprintf(stderr, "update check failed: %v\n", err)
		printConnections(stderr)
		return exitInvalid
	}
	if *asJSON {
		encodeJSONLine(stdout, updateReport{Running: verdict.Running.String(), Latest: verdict.Latest.Version.String(),
			Page: verdict.Latest.Page, Newer: verdict.Newer, Connections: connections()})
		return exitOK
	}
	switch {
	case verdict.Newer:
		fmt.Fprintf(stdout, "a newer release is published: %s (this is %s)\n  %s\n", verdict.Latest.Version, verdict.Running, verdict.Latest.Page)
	case verdict.Latest.Version == verdict.Running:
		fmt.Fprintf(stdout, "trebaruna %s is the newest published release\n", verdict.Running)
	default:
		fmt.Fprintf(stdout, "trebaruna %s is newer than the newest published release, %s\n", verdict.Running, verdict.Latest.Version)
	}
	printConnections(stdout)
	return exitOK
}
