package cli

import "os"

// Environment variables that carry secrets instead of flags.
//
// A flag is part of the command line, and every local user can read any
// process's command line (`ps -ef`, /proc/PID/cmdline). The environment of a
// process is readable only by its owner, so the desktop app — and any script
// that cares — hands secrets over this way. The flags keep working for
// interactive use.
const (
	passphraseVariable = "TREBARUNA_PASSPHRASE"
	pinVariable        = "TREBARUNA_PIN"
	tsaSecretVariable  = "TREBARUNA_TSA_PASS"
	// The card management secrets have no flags at all: they are only ever
	// typed by a person, and a person can set them without echo.
	pukVariable    = "TREBARUNA_PUK"
	newPINVariable = "TREBARUNA_NEW_PIN"
)

// secretFrom prefers an explicit flag and falls back to the environment.
func secretFrom(flagValue, variable string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(variable)
}
