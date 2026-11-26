// Package fakecmd makes the stand-ins the tests run in place of trebaruna and
// of the browser. A stand-in is a shell script: on Linux and macOS the script
// is the file itself. Windows cannot execute a script, so there the stand-in
// is a copy of the test binary, which finds the script beside itself and runs
// it with the Git Bash that the Windows runner ships with. The script is the
// same on every system, so its paths are written with forward slashes.
package fakecmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// bodySuffix names the script that sits beside a Windows stand-in.
const bodySuffix = ".sh"

func init() {
	if runtime.GOOS != "windows" {
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	script := self + bodySuffix
	if _, err := os.Stat(script); err != nil {
		return // the test binary itself, not a stand-in
	}
	if err := confine(); err != nil {
		fmt.Fprintln(os.Stderr, "fakecmd:", err)
	}
	os.Exit(runScript(filepath.ToSlash(script), os.Args[1:]))
}

// Script writes a stand-in named name in directory that runs body in sh and
// returns the path to execute. The body is sh's; a path in it must be
// written with forward slashes (filepath.ToSlash), as sh reads it.
func Script(t *testing.T, directory, name, body string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := filepath.Join(directory, name+".exe")
	if err := placeTestBinary(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+bodySuffix, []byte(body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// placeTestBinary puts a copy of the running test binary at path: a hard link
// when the folder shares its volume, a copy otherwise.
func placeTestBinary(path string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.Link(self, path); err == nil {
		return nil
	}
	content, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o755)
}

// runScript runs the script with the arguments the stand-in was given, and
// returns the status it exits with.
func runScript(script string, arguments []string) int {
	bash, err := bashPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 127
	}
	command := exec.Command(bash, append([]string{script}, arguments...)...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = command.Run()
	var exited *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exited):
		return exited.ExitCode()
	}
	fmt.Fprintln(os.Stderr, err)
	return 127
}

// bashPath finds the bash of Git for Windows, which sits in bin beside the
// cmd folder that holds git.exe. The bash in System32, when there is one, is
// not the shell the scripts are written for.
func bashPath() (string, error) {
	if git, err := exec.LookPath("git"); err == nil {
		candidate := filepath.Join(filepath.Dir(filepath.Dir(git)), "bin", "bash.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return exec.LookPath("bash")
}
