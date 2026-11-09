//go:build gui

package infrastructure

import "time"

// background runs work off the UI thread; the work reports back through
// fyne.Do.
//
// It is a field rather than a bare `go` so the acceptance tests can run the
// work in line: the Fyne test driver runs fyne.Do on the calling goroutine,
// so work left running would change widgets under the test, or under the next
// one, and crash inside Fyne's caches.
type background func(work func())

// offThread is the production runner.
func offThread(work func()) { go work() }

// inLine runs the work at once, on the caller's goroutine; tests only.
func inLine(work func()) { work() }

// typingPause is how long the form waits after the last keystroke before it
// opens a certificate with the passphrase typed so far.
const typingPause = 600 * time.Millisecond
