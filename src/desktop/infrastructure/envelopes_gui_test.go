//go:build gui

package infrastructure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

// envelopeCommand stands in for trebaruna: certificates are named after
// their file, an envelope is written beside its document, and an envelope
// opens to its document. It records the decrypt arguments.
func envelopeCommand(t *testing.T) (binary, decrypted string) {
	t.Helper()
	directory := t.TempDir()
	binary = filepath.Join(directory, "trebaruna")
	decrypted = filepath.Join(directory, "decrypt")
	script := `#!/bin/sh
case "$1" in
certificate)
  case "$2" in
  *mario*) name="MARIO ROSSI" ;;
  *) name="ANNA BIANCHI" ;;
  esac
  echo '{"certificates":[{"name":"'"$name"'","not_after":"2030-01-01T00:00:00Z"}]}' ;;
encrypt)
  echo '{"path":"'"$2"'.p7e","size":4096,"recipients":["ANNA BIANCHI"]}' ;;
decrypt)
  printf '%s\n' "$@" > ` + decrypted + `
  echo '{"path":"/tmp/offerta.pdf","size":2048}' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return binary, decrypted
}

// TestTheEnvelopesWindowEncryptsAndOpens: a document encrypted for a
// recipient read from their certificate, and an envelope opened with the
// key chosen in the signing tab, which the window follows.
func TestTheEnvelopesWindowEncryptsAndOpens(t *testing.T) {
	test.NewTempApp(t)
	binary, decrypted := envelopeCommand(t)
	desktop := newDesktop(test.NewTempWindow(t, nil), messaging.For(messaging.Spanish), binary)
	desktop.window.SetContent(desktop.withTabs(desktop.buildContent("")))
	m := desktop.messages

	desktop.showEnvelopes("")
	panel := desktop.envelopes
	if panel == nil {
		t.Fatal("the envelopes window did not open")
	}

	// Encrypting: nothing for nobody, then the recipient by name.
	panel.encryptDocument()
	if panel.encryptStatus.Text != m.MissingDocument || panel.encryptStatus.Importance != widget.DangerImportance {
		t.Errorf("no document: %q", panel.encryptStatus.Text)
	}
	panel.setDocument("/tmp/offerta.pdf")
	panel.encryptDocument()
	if panel.encryptStatus.Text != m.MissingRecipient {
		t.Errorf("no recipient: %q", panel.encryptStatus.Text)
	}
	panel.addRecipient("/tmp/anna.pem")
	settle(t, func() bool { return len(panel.recipients) == 1 })
	if panel.recipients[0].holder != "ANNA BIANCHI" {
		t.Errorf("recipient: %+v", panel.recipients[0])
	}
	panel.addRecipient("/tmp/anna.pem")
	panel.encryptDocument()
	settle(t, func() bool { return panel.encryptStatus.Importance == widget.SuccessImportance })
	if want := "offerta.pdf.p7e"; !strings.Contains(panel.encryptStatus.Text, want) || !strings.Contains(panel.encryptStatus.Text, "ANNA BIANCHI") {
		t.Errorf("encrypted: %q", panel.encryptStatus.Text)
	}
	if len(panel.recipients) != 1 {
		t.Error("a certificate added twice is listed once")
	}
	panel.removeRecipient("/tmp/anna.pem")
	if len(panel.recipients) != 0 {
		t.Error("the recipient was not removed")
	}

	// Opening: no key yet, then the one chosen to sign.
	if panel.keyLine.Text != m.NoKeyToOpen || !panel.keyRow.Visible() {
		t.Errorf("without a key: %q", panel.keyLine.Text)
	}
	panel.setEnvelope("/tmp/offerta.pdf.p7e")
	panel.openEnvelope()
	if panel.openStatus.Text != m.MissingKey {
		t.Errorf("opened without a key: %q", panel.openStatus.Text)
	}
	desktop.form.passphrase.SetText("secret")
	desktop.form.setCertificate("/tmp/mario.p12")
	settle(t, func() bool { return strings.Contains(panel.keyLine.Text, "MARIO ROSSI") })
	if panel.keyRow.Visible() {
		t.Error("the button to choose a key stays once one is chosen")
	}
	panel.openEnvelope()
	settle(t, func() bool { return panel.openStatus.Importance == widget.SuccessImportance })
	if !strings.Contains(panel.openStatus.Text, "offerta.pdf (2.0 KB)") || !panel.openedRow.Visible() {
		t.Errorf("opened: %q", panel.openStatus.Text)
	}
	arguments, _ := os.ReadFile(decrypted)
	if !strings.Contains(string(arguments), "--p12\n/tmp/mario.p12") || strings.Contains(string(arguments), "secret") {
		t.Errorf("decrypt arguments: %q", arguments)
	}

	// A second request brings the same window forward.
	desktop.showEnvelopes("/tmp/otra.pdf.p7e")
	if desktop.envelopes != panel || panel.envelopePath != "/tmp/otra.pdf.p7e" {
		t.Error("a second window was opened")
	}
	panel.window.Close()
	if desktop.envelopes != nil || desktop.form.onKeyChange != nil {
		t.Error("the closed window is still followed")
	}
}

// TestADroppedEnvelopeOpensTheEnvelopesWindow: a .p7e dropped on the main
// window is not a document to sign.
func TestADroppedEnvelopeOpensTheEnvelopesWindow(t *testing.T) {
	test.NewTempApp(t)
	binary, _ := envelopeCommand(t)
	desktop := newDesktop(test.NewTempWindow(t, nil), messaging.For(messaging.Spanish), binary)
	desktop.window.SetContent(desktop.withTabs(desktop.buildContent("")))

	desktop.dropped("/tmp/offerta.pdf.p7e", false, func(string) { t.Error("an envelope is not checked") })
	if desktop.envelopes == nil || desktop.envelopes.envelopePath != "/tmp/offerta.pdf.p7e" {
		t.Fatal("the envelope did not reach the envelopes window")
	}
	if desktop.form.document != "" {
		t.Error("the envelope became the document to sign")
	}
	fyne.DoAndWait(func() {})
}
