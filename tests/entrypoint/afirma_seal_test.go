package cli_test

// visibleSignature through `trebaruna afirma --interactive`: the window
// gets a private copy of the PDF to place the seal on, removed once it
// has decided, and the signature's seal lands in the box it sent back.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
)

func TestTheWindowPlacesTheSealOnAPrivateCopy(t *testing.T) {
	pdf, err := os.ReadFile(writeOnePagePDF(t))
	if err != nil {
		t.Fatal(err)
	}
	key := writeIdentityP12(t, "segreto", "MARIA GARCIA", 36)
	uri := "afirma://sign?format=PAdES&algorithm=SHA256withRSA&appname=SEDE&properties=" +
		url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("visibleSignature=want"))) +
		"&dat=" + url.QueryEscape(base64.StdEncoding.EncodeToString(pdf))

	decisions, decide := io.Pipe()
	printed, output := io.Pipe()
	exited := make(chan int, 1)
	go func() {
		exited <- cli.RunIO([]string{"afirma", uri, "--interactive"}, decisions, output, io.Discard)
		output.Close()
	}()
	lines := bufio.NewScanner(printed)
	lines.Buffer(make([]byte, 1<<20), 1<<24)
	next := func() map[string]any {
		t.Helper()
		if !lines.Scan() {
			t.Fatal("the command printed nothing more")
		}
		var line map[string]any
		if err := json.Unmarshal(lines.Bytes(), &line); err != nil {
			t.Fatalf("not a JSON line: %q", lines.Text())
		}
		return line
	}

	proposal := next()
	copyPath, _ := proposal["seal_document"].(string)
	if proposal["seal"] != "want" || copyPath == "" {
		t.Fatalf("the proposal asks to place the seal on a copy: %v", proposal)
	}
	info, err := os.Stat(copyPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the copy is the user's alone: %v %v", info, err)
	}
	if content, _ := os.ReadFile(copyPath); string(content) != string(pdf) {
		t.Error("the copy is the page's PDF")
	}

	io.WriteString(decide, `{"approved":true,"key":{"p12":"`+key+`"},"passphrase":"segreto",`+
		`"seal":{"page":1,"llx":300,"lly":60,"urx":520,"ury":120}}`+"\n")
	outcome := next()
	decide.Close()
	if code := <-exited; code != 0 {
		t.Errorf("exit %d", code)
	}
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Error("the copy is removed once decided")
	}

	answer, _ := outcome["answer"].(string)
	_, encoded, _ := strings.Cut(answer, "|")
	signed, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("the answer: %q", answer)
	}
	match := widgetRect.FindStringSubmatch(string(signed))
	if match == nil {
		t.Fatal("the signature has no visible seal")
	}
	for index, want := range []float64{300, 60, 520, 120} {
		if got, _ := strconv.ParseFloat(match[index+1], 64); got != want {
			t.Errorf("the seal's box %v, want 300 60 520 120", match[1:])
			break
		}
	}
}
