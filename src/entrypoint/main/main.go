// Command firma-it is the console entry point.
package main

import (
	"os"

	"codeberg.org/simplicer/firma-it/src/entrypoint/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
