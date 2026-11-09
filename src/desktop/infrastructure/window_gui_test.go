//go:build gui

package infrastructure

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/domain"
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
	if menu == nil || len(menu.Items) != 5 {
		t.Fatalf("main menu = %v, want File, Signature, Card, Tools and Help", menu)
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
	card := menu.Items[2]
	if card.Label != m.MenuCard || len(card.Items) != 2 ||
		card.Items[0].Label != m.MenuChangePIN || card.Items[1].Label != m.MenuUnlockPIN {
		t.Errorf("the Card menu must offer changing and unlocking the PIN: %+v", card)
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
	tab.background = inLine
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

type networkedSigner struct{}

func (networkedSigner) Sign(_ context.Context, intent domain.SigningIntent) (domain.Receipt, error) {
	return domain.Receipt{SignedPath: intent.OutputName(), Network: []transparency.Connection{
		{Purpose: transparency.PurposeTimestamp, Method: "POST", URL: "https://tsa.example/tsa", Status: 200, SentBytes: 77, Received: 2152, Via: "library"},
	}}, nil
}

func TestTheConnectionsOfASignatureAreSaidAndKept(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	form.signing = application.NewSignFromDesktop(networkedSigner{}, func(string) bool { return true })
	form.setDocument("/tmp/offerta.docx")
	form.setCertificate("/tmp/rossi.p12")

	test.Tap(form.signButton)
	settle(t, func() bool { return form.afterSign.Visible() })

	if !strings.Contains(form.status.Text, "tsa.example (sello de tiempo)") {
		t.Errorf("status = %q, want the authority named", form.status.Text)
	}
	if entries := fixture.desktop.activity.list(); len(entries) != 1 || entries[0].Host() != "tsa.example" {
		t.Errorf("session activity = %+v", entries)
	}
}

func TestTheActivityWindowListsOrSaysThereIsNothing(t *testing.T) {
	test.NewTempApp(t)
	m := messaging.For(messaging.Spanish)

	empty := activityContent(nil, m)
	if label, ok := empty.(*fyne.Container).Objects[0].(*widget.Label); !ok || label.Text != m.NetworkEmpty {
		t.Errorf("empty state = %#v", empty)
	}

	listing := activityContent([]transparency.Connection{
		{Purpose: transparency.PurposeRevocation, Method: "POST", URL: "http://ocsp.example/", Status: 200},
		{Purpose: transparency.PurposeUnattributed, Method: "GET", URL: "https://elsewhere.example/x", Error: "dial tcp: refused", Via: "library"},
	}, m)
	window := test.NewTempWindow(t, listing)
	window.Resize(fyne.NewSize(700, 400))
	texts := collectTexts(window.Content())
	for _, want := range []string{"consulta de revocación: ocsp.example", "sin motivo identificado: elsewhere.example", "dial tcp: refused", m.NetworkViaLibrary} {
		if !strings.Contains(texts, want) {
			t.Errorf("the listing lacks %q", want)
		}
	}
}

// collectTexts joins every label's text under an object.
func collectTexts(object fyne.CanvasObject) string {
	var builder strings.Builder
	var visit func(fyne.CanvasObject)
	visit = func(current fyne.CanvasObject) {
		switch typed := current.(type) {
		case *widget.Label:
			builder.WriteString(typed.Text + "\n")
		case *fyne.Container:
			for _, child := range typed.Objects {
				visit(child)
			}
		case *container.Scroll:
			visit(typed.Content)
		}
	}
	visit(object)
	return builder.String()
}

func TestAboutReadsTheBuildTheCommandDescribes(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "trebaruna")
	script := "#!/bin/sh\necho '{\"version\":\"0.9.0-unstable\",\"go\":\"go1.27\",\"platform\":\"linux/amd64\",\"pkcs11\":true," +
		"\"dependencies\":[{\"path\":\"fyne.io/fyne/v2\",\"version\":\"v2.8.2\",\"license\":\"BSD-3-Clause\"}]}'\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	test.NewTempApp(t)
	desktop := newDesktop(test.NewTempWindow(t, nil), messaging.For(messaging.Spanish), binary)

	build, err := desktop.describeBuild()
	if err != nil {
		t.Fatalf("describeBuild: %v", err)
	}
	if build.Version != "0.9.0-unstable" || !build.PKCS11 || len(build.Dependencies) != 1 || build.Dependencies[0].License != "BSD-3-Clause" {
		t.Errorf("build = %+v", build)
	}
	desktop.showAbout() // must build the dialog without failing
}

func TestAnEnvelopeOffersItsDocument(t *testing.T) {
	tab := verificationFor(t)
	report := decodeReport(t, `{"signed":true,"verdict":"advanced","signers":[{"signer":"MARIO ROSSI","integrity":"good"}]}`)

	tab.path = "/tmp/atto.pdf.p7m"
	tab.render(report)
	if !tab.extract.Visible() {
		t.Error("a .p7m must offer its document")
	}
	tab.path = "/tmp/atto_signed.pdf"
	tab.render(report)
	if tab.extract.Visible() {
		t.Error("a signed PDF is its own document")
	}
}

func TestExtractionNeverTakesAnOccupiedName(t *testing.T) {
	directory := t.TempDir()
	taken := filepath.Join(directory, "atto.pdf")
	if err := os.WriteFile(taken, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := freeName(taken); got != filepath.Join(directory, "atto (2).pdf") {
		t.Errorf("freeName = %q", got)
	}
	if got := freeName(filepath.Join(directory, "nuovo.pdf")); got != filepath.Join(directory, "nuovo.pdf") {
		t.Errorf("a free name must be kept, got %q", got)
	}
}

func TestExtractingReportsWhereTheDocumentWent(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "trebaruna")
	script := "#!/bin/sh\necho '{\"layers\":1}'\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	tab := verificationFor(t)
	tab.binary = binary
	tab.path = filepath.Join(directory, "atto.pdf.p7m")
	var opened string
	tab.open = func(path string) { opened = path }

	tab.extractDocument()
	settle(t, func() bool { return tab.extracted.Visible() })
	if tab.extracted.Importance != widget.SuccessImportance || !strings.Contains(tab.extracted.Text, "atto.pdf") {
		t.Errorf("extracted = %q", tab.extracted.Text)
	}
	if opened != filepath.Join(directory, "atto.pdf") {
		t.Errorf("opened %q, want the extracted document", opened)
	}
}

type collectingSigner struct {
	mu      sync.Mutex
	intents []domain.SigningIntent
}

func (s *collectingSigner) Sign(_ context.Context, intent domain.SigningIntent) (domain.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.intents = append(s.intents, intent)
	if strings.HasSuffix(intent.DocumentPath, "rotto.txt") {
		return domain.Receipt{}, errors.New("unreadable")
	}
	return domain.Receipt{SignedPath: intent.OutputName()}, nil
}

func TestABatchSignsEachDocumentInItsFormat(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	signer := &collectingSigner{}
	form.signing = application.NewSignFromDesktop(signer, func(string) bool { return true })
	form.setCertificate("/tmp/rossi.p12")

	form.setDocuments([]string{"/tmp/a.pdf", "/tmp/b.xml", "/tmp/rotto.txt"})
	if form.format != domain.FormatEach || len(form.formatChoice.Options) != 4 {
		t.Fatalf("format %s, options %v", form.format, form.formatChoice.Options)
	}
	test.Tap(form.signButton)
	settle(t, func() bool { return strings.HasPrefix(form.status.Text, "Firmados") })

	signer.mu.Lock()
	defer signer.mu.Unlock()
	formats := []domain.SignatureFormat{}
	for _, intent := range signer.intents {
		formats = append(formats, intent.Format)
	}
	if len(formats) != 3 || formats[0] != domain.FormatPAdES || formats[1] != domain.FormatXAdES || formats[2] != domain.FormatCAdES {
		t.Errorf("formats = %v", formats)
	}
	if !strings.Contains(form.status.Text, "Firmados 2 de 3") || !strings.Contains(form.status.Text, "rotto.txt") || form.status.Importance != widget.WarningImportance {
		t.Errorf("status = %q", form.status.Text)
	}
}

func TestAFolderOffersWhatIsWorthSigning(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"contratto.pdf", "fattura.xml", "contratto_signed.pdf", "vecchio.pdf.p7m", "chiave.p12", ".nascosto"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := documentsIn(directory)
	if len(got) != 2 || filepath.Base(got[0]) != "contratto.pdf" || filepath.Base(got[1]) != "fattura.xml" {
		t.Errorf("documentsIn = %v", got)
	}
}
