// Command trebaruna is the console entry point.
package main

import (
	"os"

	"codeberg.org/anvius/trebaruna/src/entrypoint/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
