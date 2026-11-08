package infrastructure

import (
	"fmt"
	"os"
	"path/filepath"

	"codeberg.org/anvius/pignus/src/signing/application"
)

// DiskStore reads and writes documents on the local filesystem.
type DiskStore struct{}

// Read returns the file content.
func (DiskStore) Read(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return content, nil
}

// Write stores the content, creating parent directories when needed and
// refusing to overwrite unless the caller allowed it.
//
// Overwriting matters: signing twice onto the same name silently destroys the
// first signature, which is exactly the sort of data loss a signature tool must
// never cause.
func (DiskStore) Write(path string, content []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", directory, err)
	}

	// Write to a temporary file in the same directory, then rename: a crash
	// mid-write must not leave a truncated signature behind.
	temporary, err := os.CreateTemp(directory, ".pignus-*")
	if err != nil {
		return fmt.Errorf("create temporary file in %s: %w", directory, err)
	}
	temporaryName := temporary.Name()

	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		os.Remove(temporaryName)
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Chmod(temporaryName, 0o644); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("set permissions on %s: %w", temporaryName, err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("move %s into place: %w", temporaryName, err)
	}
	return nil
}

// compile-time check.
var _ application.FileStore = DiskStore{}
