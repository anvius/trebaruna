// Command pignus is the console entry point.
package main

import (
	"os"

	"codeberg.org/anvius/pignus/src/entrypoint/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
