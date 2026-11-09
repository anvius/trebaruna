//go:build gui

package infrastructure

import (
	"encoding/json"
	"testing"

	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"

	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	reportmessaging "codeberg.org/simplicer/trebaruna/src/verification/messaging"
)

func TestADroppedFileGoesWhereItBelongs(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	desktop := fixture.desktop
	var checked []string
	check := func(path string) { checked = append(checked, path) }

	desktop.dropped("/tmp/rossi.PFX", true, check)
	desktop.dropped("/tmp/offerta.docx", false, check)
	desktop.dropped("/tmp/contratto_signed.pdf", true, check)

	if desktop.form.certificate != "/tmp/rossi.PFX" {
		t.Errorf("certificate = %q: a key bundle goes to step 2 from any tab", desktop.form.certificate)
	}
	if desktop.form.document != "/tmp/offerta.docx" {
		t.Errorf("document = %q: on the signing tab a file is signed", desktop.form.document)
	}
	if len(checked) != 1 || checked[0] != "/tmp/contratto_signed.pdf" {
		t.Errorf("checked = %v: on the verification tab a file is checked", checked)
	}
}

func TestTheMenuNamesEveryActionWithItsShortcut(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	menu := fixture.desktop.window.MainMenu()
	if menu == nil || len(menu.Items) != 4 {
		t.Fatalf("main menu = %v, want File, Signature, Tools and Help", menu)
	}

	m := fixture.desktop.messages
	wanted := map[string]bool{
		m.MenuOpenDocument: true, m.MenuChooseCertificate: true, m.MenuCheckDocument: true,
		m.SignButton: true, m.MenuPreviousPage: true, m.MenuNextPage: true, m.SuggestButton: true,
	}
	for _, top := range menu.Items {
		for _, item := range top.Items {
			if wanted[item.Label] {
				if item.Shortcut == nil {
					t.Errorf("%q has no shortcut", item.Label)
				}
				delete(wanted, item.Label)
			}
		}
	}
	for label := range wanted {
		t.Errorf("the menu lacks %q", label)
	}
}

func TestRequestsLiveInTheMenuNotInATab(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	tabs, ok := fixture.desktop.window.Content().(*container.AppTabs)
	if !ok || len(tabs.Items) != 2 {
		t.Fatalf("content = %T with %d tabs, want Sign and Check only", fixture.desktop.window.Content(), len(tabs.Items))
	}
}

func verificationFor(t *testing.T) *verificationTab {
	t.Helper()
	test.NewTempApp(t)
	tab := newVerificationTab(test.NewTempWindow(t, nil), messaging.For(messaging.Spanish),
		reportmessaging.For("es"), DefaultPalette(), "trebaruna")
	tab.content()
	return tab
}

func decodeReport(t *testing.T, raw string) verifyReport {
	t.Helper()
	var report verifyReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestAVerdictIsAWordASentenceAndAColour(t *testing.T) {
	tab := verificationFor(t)
	cases := []struct {
		verdict     string
		explanation string
		colour      any
	}{
		{"qualified", tab.ui.ExplainQualified, tab.palette.Success},
		{"untrusted", tab.ui.ExplainUntrusted, tab.palette.Warning},
		{"invalid", tab.ui.ExplainInvalid, tab.palette.Danger},
		{"broken", tab.ui.ExplainBroken, tab.palette.Danger},
	}
	for _, testCase := range cases {
		tab.render(decodeReport(t, `{"signed":true,"verdict":"`+testCase.verdict+`","signers":[{"signer":"MARIO ROSSI","integrity":"good"}]}`))
		if tab.verdict.Text == "" || tab.explanation.Text != testCase.explanation || tab.verdict.Color != testCase.colour {
			t.Errorf("%s: verdict %q, explanation %q, colour %v", testCase.verdict, tab.verdict.Text, tab.explanation.Text, tab.verdict.Color)
		}
	}
}

func TestEachSignatureGetsItsOwnBlock(t *testing.T) {
	tab := verificationFor(t)
	tab.render(decodeReport(t, `{"signed":true,"verdict":"advanced","signers":[
		{"signer":"MARIO ROSSI","identifier":"TINIT-RSSMRA80A01H501U","integrity":"good",
		 "findings":[{"code":"x","status":"good","message":"fine"},{"code":"y","status":"warn","message":"no timestamp"}]},
		{"signer":"ANNA BIANCHI","integrity":"good"}]}`))

	if len(tab.signers.Objects) != 2 {
		t.Fatalf("got %d blocks, want one per signature", len(tab.signers.Objects))
	}
}

func TestAnUnsignedFileSaysSo(t *testing.T) {
	tab := verificationFor(t)
	tab.render(decodeReport(t, `{"signed":false,"verdict":"unknown"}`))
	if tab.verdict.Text != tab.report.NoSignatures || len(tab.signers.Objects) != 0 {
		t.Errorf("verdict %q with %d blocks", tab.verdict.Text, len(tab.signers.Objects))
	}
}

func TestCheckingWithoutAFileAsksForOne(t *testing.T) {
	tab := verificationFor(t)
	tab.run()
	if tab.verdict.Text != tab.ui.MissingDocument {
		t.Errorf("verdict = %q", tab.verdict.Text)
	}
}

func TestSigningTimesReadLikeTheSeal(t *testing.T) {
	if got := readableInstant("2026-11-09T10:12:03+01:00"); got != "09/11/2026 10:12:03 +01:00" {
		t.Errorf("readableInstant = %q", got)
	}
	if got := readableInstant("yesterday"); got != "yesterday" {
		t.Errorf("an unparsable value must pass through, got %q", got)
	}
}
