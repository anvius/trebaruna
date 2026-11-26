//go:build !windows

package fakecmd

// confine does nothing here: a stand-in is a shell script, and killing it ends
// the script and its children.
func confine() error { return nil }
