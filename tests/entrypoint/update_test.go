package cli_test

// `update` asks where trebaruna is published for its newest release and
// says where it is, listing the one connection; it downloads nothing, and
// a build that does not know its version asks nothing.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestABuildThatDoesNotKnowItsVersionAsksNothing(t *testing.T) {
	asked := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked++ }))
	defer server.Close()
	_, stderr, code := run("update", "--from", server.URL+"/simplicer/trebaruna")
	if code == 0 || !strings.Contains(stderr, "does not know its version") || asked != 0 {
		t.Errorf("exit %d, asked %d: %s", code, asked, stderr)
	}
}

func TestTheUpdateCheckSaysWhereTheNewerReleaseIs(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the command")
	}
	binary := filepath.Join(t.TempDir(), "trebaruna")
	build := exec.Command("go", "build", "-o", binary, "-ldflags",
		"-X codeberg.org/simplicer/trebaruna/src/entrypoint/cli.injectedVersion=0.105.0-unstable", "./src/entrypoint/main")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	tags := `[{"name":"v0.106.0-unstable"},{"name":"v0.20.5-unstable"}]`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte(tags))
	}))
	defer server.Close()
	repository := server.URL + "/simplicer/trebaruna"

	output, err := exec.Command(binary, "update", "--from", repository).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "a newer release is published: 0.106.0-unstable (this is 0.105.0-unstable)") ||
		!strings.Contains(string(output), repository+"/releases/tag/v0.106.0-unstable") || !strings.Contains(string(output), "update-check GET") {
		t.Errorf("%v\n%s", err, output)
	}
	output, err = exec.Command(binary, "update", "--from", repository, "--json").Output()
	var report struct {
		Running, Latest, Page string
		Newer                 bool
		Connections           []struct{ Purpose string }
	}
	if err != nil || json.Unmarshal(output, &report) != nil || !report.Newer || report.Latest != "0.106.0-unstable" ||
		len(report.Connections) != 1 || report.Connections[0].Purpose != "update-check" {
		t.Errorf("%v %s", err, output)
	}

	tags = `[{"name":"v0.105.0-unstable"}]`
	if output, _ := exec.Command(binary, "update", "--from", repository).CombinedOutput(); !strings.Contains(string(output), "0.105.0-unstable is the newest published release") {
		t.Errorf("up to date: %s", output)
	}
	tags = `[{"name":"v0.20.5-unstable"}]`
	if output, _ := exec.Command(binary, "update", "--from", repository).CombinedOutput(); !strings.Contains(string(output), "newer than the newest published release, 0.20.5-unstable") {
		t.Errorf("ahead: %s", output)
	}
}
