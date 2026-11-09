package transparency_test

// ADR-0010: every connection is recorded. The only way to guarantee it is that
// no code outside the transparency slice builds an HTTP client of its own, so
// this test reads the source tree and fails on any that does.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var unrecordedNetwork = regexp.MustCompile(
	`http\.Client\{|http\.DefaultClient|http\.DefaultTransport|http\.Get\(|http\.Post\(|http\.Head\(|http\.PostForm\(|net\.Dial\(|tls\.Dial\(`)

func TestNoCodeOpensAnUnrecordedConnection(t *testing.T) {
	root := filepath.Join("..", "..", "src")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == "transparency" {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for number, line := range strings.Split(string(content), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if unrecordedNetwork.MatchString(line) {
				t.Errorf("%s:%d opens a connection outside the transparency slice: %s",
					path, number+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
