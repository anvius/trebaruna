// Package portable holds what the tests need to behave the same on Linux,
// macOS and Windows: where a program's configuration lives, which file modes
// mean something, and how openssl and the other tools write their output.
package portable

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// PosixModes reports whether POSIX permission bits mean anything here. They
// do not on Windows, where a file's privacy is its ACL, inherited from the
// user's profile; the tests that check modes skip that check there.
func PosixModes() bool { return runtime.GOOS != "windows" }

// IsolateUserConfig points os.UserConfigDir at a folder under t.TempDir() and
// returns the folder. The variable that moves it differs by system: it is
// XDG_CONFIG_HOME on Linux, HOME on macOS and APPDATA on Windows.
func IsolateUserConfig(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", root)
	case "windows":
		t.Setenv("APPDATA", root)
	default:
		t.Setenv("XDG_CONFIG_HOME", root)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	return base
}

// SubjectFile writes an openssl configuration that names subject, given as
// an openssl -subj value such as "/C=DE/O=Ärztekammer/CN=HBA-CA 7", in UTF-8,
// and returns its path, for "-config". openssl reads its command line in the
// system's code page on Windows, so a name with an umlaut cannot be passed
// with -subj there; a file is read as the bytes it holds.
func SubjectFile(t *testing.T, directory, subject string) string {
	t.Helper()
	var name strings.Builder
	name.WriteString("[req]\ndistinguished_name = subject\nprompt = no\nutf8 = yes\n[subject]\n")
	for _, part := range strings.Split(strings.TrimPrefix(subject, "/"), "/") {
		key, value, found := strings.Cut(part, "=")
		if !found {
			t.Fatalf("subject %q: %q is not NAME=value", subject, part)
		}
		name.WriteString(key + " = " + value + "\n")
	}
	path := filepath.Join(directory, "subject-"+strings.Map(safe, subject)+".cnf")
	if err := os.WriteFile(path, []byte(name.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// safe keeps a file name to letters and digits.
func safe(r rune) rune {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
		return r
	}
	return '_'
}

// LF turns the CRLF line ends that a Windows text-mode write leaves in a tool's
// output back into LF, so the text compares as the tool wrote it on Linux.
// openssl, Java, xmllint and pdftotext all write text this way on Windows.
func LF(output []byte) []byte {
	return bytes.ReplaceAll(output, []byte("\r\n"), []byte("\n"))
}
