//go:build gui

package infrastructure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

// texts gathers every label's text under an object.
func texts(object fyne.CanvasObject) string {
	switch typed := object.(type) {
	case *widget.Label:
		return typed.Text + "\n"
	case *fyne.Container:
		all := ""
		for _, child := range typed.Objects {
			all += texts(child)
		}
		return all
	}
	return ""
}

// TestCounterSignaturesHangUnderWhatTheySign, indented, in order.
func TestCounterSignaturesHangUnderWhatTheySign(t *testing.T) {
	tab := verificationFor(t)
	tab.render(decodeReport(t, `{"signed":true,"verdict":"advanced","signers":[
		{"field":"1","signer":"MARIO ROSSI","integrity":"good"},
		{"field":"2","signer":"ANNA BIANCHI","integrity":"good"},
		{"field":"1.1","countersigns":"1","signer":"NOTAIO VERDI","integrity":"good"}]}`))
	if len(tab.signers.Objects) != 3 {
		t.Fatalf("%d blocks", len(tab.signers.Objects))
	}
	order := []string{"MARIO ROSSI", "NOTAIO VERDI", "ANNA BIANCHI"}
	for index, name := range order {
		if !strings.Contains(texts(tab.signers.Objects[index]), name) {
			t.Errorf("block %d is not %s: %q", index, name, texts(tab.signers.Objects[index]))
		}
	}
	border, ok := tab.signers.Objects[1].(*fyne.Container)
	if !ok || len(border.Objects) != 2 {
		t.Errorf("the counter-signature must sit beside an indent, got %T", tab.signers.Objects[1])
	}
}

// TestAContainerSignatureSaysWhatItCovers and what nobody signed.
func TestAContainerSignatureSaysWhatItCovers(t *testing.T) {
	tab := verificationFor(t)
	tab.path = "/tmp/expediente.asice"
	tab.render(decodeReport(t, `{"signed":true,"verdict":"advanced","signers":[{"field":"META-INF/signatures.xml","signer":"MARIO ROSSI","integrity":"good",
		"findings":[{"code":"container.covers","status":"good","message":"covers","detail":"acta.txt, plano.pdf"},
		{"code":"container.unsigned_files","status":"warn","message":"unsigned","detail":"notas.txt"}]}]}`))
	shown := texts(tab.signers.Objects[0])
	if !strings.Contains(shown, "acta.txt, plano.pdf") || !strings.Contains(shown, "notas.txt") {
		t.Errorf("block: %q", shown)
	}
	if !tab.extract.Visible() || tab.extract.Text != tab.ui.ExtractDocumentsButton {
		t.Errorf("a container offers its documents: %q", tab.extract.Text)
	}
	tab.path = "/tmp/atto.pdf.p7m.tsd"
	tab.render(decodeReport(t, `{"signed":true,"verdict":"advanced","signers":[{"signer":"X","integrity":"good"}]}`))
	if !tab.extract.Visible() || tab.extract.Text != tab.ui.ExtractButton {
		t.Errorf("time-stamped data offers its document: %q", tab.extract.Text)
	}
	if !tab.saveReport.Visible() {
		t.Error("a verified file can be reported")
	}
}

// fakeCommand writes a script standing in for the command line.
func fakeCommand(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trebaruna")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAContainersDocumentsGoToAFolder.
func TestAContainersDocumentsGoToAFolder(t *testing.T) {
	directory := t.TempDir()
	tab := verificationFor(t)
	tab.binary = fakeCommand(t, `[ "$1 $2" = "asic --extract" ] || exit 3; mkdir -p "$5"`)
	tab.path = filepath.Join(directory, "expediente.asice")
	var opened string
	tab.open = func(path string) { opened = path }
	tab.extractDocument()
	settle(t, func() bool { return tab.extracted.Visible() })
	if tab.extracted.Importance != widget.SuccessImportance || opened != filepath.Join(directory, "expediente") {
		t.Errorf("extracted %q (%v), opened %q", tab.extracted.Text, tab.extracted.Importance, opened)
	}
}

// TestTheReportIsSavedAndOpened, and a failure says why.
func TestTheReportIsSavedAndOpened(t *testing.T) {
	tab := verificationFor(t)
	tab.path = "/tmp/acta.pdf"
	tab.render(decodeReport(t, `{"signed":true,"verdict":"advanced","signers":[{"signer":"X","integrity":"good"}]}`))
	tab.binary = fakeCommand(t, `while [ $# -gt 0 ]; do [ "$1" = "--report" ] && echo informe > "$2"; shift; done`)
	destination := filepath.Join(t.TempDir(), "acta - informe.pdf")
	var opened string
	tab.open = func(path string) { opened = path }
	tab.writeReport(destination)
	settle(t, func() bool { return tab.reported.Visible() })
	if tab.reported.Importance != widget.SuccessImportance || opened != destination {
		t.Errorf("reported %q, opened %q", tab.reported.Text, opened)
	}

	tab.binary = fakeCommand(t, `echo "report: a report is .md, .html or .pdf" >&2; exit 64`)
	tab.writeReport(filepath.Join(t.TempDir(), "nothing.pdf"))
	settle(t, func() bool { return tab.reported.Importance == widget.DangerImportance })
	if !strings.Contains(tab.reported.Text, "report") {
		t.Errorf("failure: %q", tab.reported.Text)
	}
}
