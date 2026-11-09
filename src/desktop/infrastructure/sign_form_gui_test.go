//go:build gui

package infrastructure

// Acceptance tests for the signing form: the whole tab with the command-line
// ports replaced by scripted ones, driven the way a user drives it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

type blankRenderer struct{}

func (blankRenderer) RenderPage(_ context.Context, _ string, page int) (application.PagePreview, error) {
	ink, _ := domain.NewInkMap(298, 421, make([]float64, 298*421))
	var encoded bytes.Buffer
	_ = png.Encode(&encoded, image.NewGray(image.Rect(0, 0, 1, 1)))
	return application.PagePreview{
		PageNumber: page, WidthPoints: 595.28, HeightPoints: 841.89, PNG: encoded.Bytes(),
		RasterWidth: 298, RasterHeight: 421, Ink: ink, PageCount: 2,
	}, nil
}

type scriptedCertificate struct {
	summary domain.CertificateSummary
	err     error
}

func (r scriptedCertificate) Read(context.Context, domain.CertificateFile) (domain.CertificateSummary, error) {
	return r.summary, r.err
}

type capturingSigner struct {
	intents chan domain.SigningIntent
	err     error
}

func (s capturingSigner) Sign(_ context.Context, intent domain.SigningIntent) (domain.Receipt, error) {
	s.intents <- intent
	return domain.Receipt{SignedPath: intent.OutputName()}, s.err
}

func qualifiedRossi() domain.CertificateSummary {
	return domain.CertificateSummary{
		Holder: "MARIO ROSSI", Identifier: "TINIT-RSSMRA80A01H501U", Issuer: "InfoCert S.p.A.",
		NotAfter: time.Now().Add(400 * 24 * time.Hour), Trusted: true, Qualified: true, Locality: "Roma",
	}
}

type formFixture struct {
	desktop *Window
	signer  capturingSigner
}

func newFormFixture(t *testing.T, reader application.CertificateReader) formFixture {
	t.Helper()
	return newFormFixtureWithCards(t, reader, &scriptedCards{})
}

// newFormFixtureWithCards is newFormFixture with the cards in the readers
// scripted too.
func newFormFixtureWithCards(t *testing.T, reader application.CertificateReader, cards *scriptedCards) formFixture {
	t.Helper()
	test.NewTempApp(t)
	// As main.go does before any widget exists.
	InstallTranslations(messaging.Spanish)
	window := test.NewTempWindow(t, nil)
	signer := capturingSigner{intents: make(chan domain.SigningIntent, 1)}

	desktop := newDesktop(window, messaging.For(messaging.Spanish), "trebaruna")
	desktop.application = application.NewSignFromDesktop(signer, func(string) bool { return true })
	desktop.inspect = application.NewInspectCertificate(reader)
	desktop.cards = application.NewListCards(cards)
	desktop.firefox = application.NewListCards(cards)
	desktop.pinChange = application.NewChangeCardPIN(&scriptedPINChanger{})
	desktop.preview = application.NewPreviewPage(blankRenderer{}, application.InkFinder{})
	desktop.formFields = application.NewListFormFields(&scriptedFields{})
	window.SetContent(desktop.withTabs(desktop.buildContent("")))
	window.Resize(fyne.NewSize(1220, 800))
	// The work the form starts runs in line: the test driver runs fyne.Do on
	// the calling goroutine, so nothing may still be running when a test ends.
	desktop.form.run, desktop.form.cards.run, desktop.pages.run = inLine, inLine, inLine
	desktop.form.pause = 0
	return formFixture{desktop: desktop, signer: signer}
}

// settle waits for the background work the form starts to report back.
func settle(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ready := false
		fyne.DoAndWait(func() { ready = done() })
		if ready {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the form never settled")
}

func TestAPDFOffersASignedPDFOrAnEnvelope(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form

	form.setDocument("/tmp/contratto.pdf")

	if len(form.formatChoice.Options) != 4 || form.format != domain.FormatPAdES {
		t.Fatalf("options %v, format %s: want PAdES first and CAdES offered", form.formatChoice.Options, form.format)
	}
	if form.documentRow.note.Text != "Se guardará como contratto_signed.pdf" {
		t.Errorf("note = %q", form.documentRow.note.Text)
	}
	settle(t, func() bool { return fixture.desktop.pages.canvas != nil })

	form.formatChoice.SetSelected(form.m.FormatCAdESLabel)
	if form.format != domain.FormatCAdES || fixture.desktop.pages.canvas != nil {
		t.Error("an envelope has no page to put a seal on")
	}
	if form.documentRow.note.Text != "Se guardará como contratto.pdf.p7m" {
		t.Errorf("note = %q after choosing the envelope", form.documentRow.note.Text)
	}
}

func TestAnyOtherFileGoesInAnEnvelopeOrBesideIt(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form

	form.setDocument("/tmp/offerta.txt")

	if form.format != domain.FormatCAdES || len(form.formatChoice.Options) != 3 {
		t.Fatalf("format %s, options %v: a .txt goes in an envelope or gets a .p7s beside it", form.format, form.formatChoice.Options)
	}
	form.formatChoice.SetSelected(form.m.FormatDetachedLabel)
	if form.format != domain.FormatCAdESDetached || form.documentRow.note.Text != "Se guardará como offerta.txt.p7s" {
		t.Errorf("format %s, note %q", form.format, form.documentRow.note.Text)
	}
}

// TestAWordFileIsSignedInsideFirst, as Office signs it, and still fits an
// envelope.
func TestAWordFileIsSignedInsideFirst(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form

	form.setDocument("/tmp/offerta.docx")

	if form.format != domain.FormatOOXML || len(form.formatChoice.Options) != 4 || form.formatChoice.Options[0] != form.m.FormatOOXMLLabel {
		t.Fatalf("format %s, options %v", form.format, form.formatChoice.Options)
	}
	if form.documentRow.note.Text != "Se guardará como offerta_signed.docx" {
		t.Errorf("note = %q", form.documentRow.note.Text)
	}
}

func TestTheCertificateFillsWhatItKnows(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form

	form.setCertificate("/tmp/rossi.p12")
	settle(t, func() bool { return form.summary != nil })

	if form.holder.Text != "MARIO ROSSI" || form.standing.Importance != widget.SuccessImportance {
		t.Errorf("holder %q, importance %v", form.holder.Text, form.standing.Importance)
	}
	if form.location.Text != "Roma" {
		t.Errorf("location = %q, want it taken from the certificate", form.location.Text)
	}
	if fixture.desktop.pages.identity.Name != "MARIO ROSSI" {
		t.Error("the seal must print the holder")
	}
	if got := fyne.CurrentApp().Preferences().String(preferenceCertificate); got != "/tmp/rossi.p12" {
		t.Errorf("remembered certificate = %q", got)
	}
}

func TestAProtectedCertificateAsksForItsPassphraseCalmly(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{err: domain.Problem{Code: domain.ProblemLockedCertificate}})
	form := fixture.desktop.form

	form.setCertificate("/tmp/rossi.p12")
	settle(t, func() bool { return form.standing.Text != form.m.CertificateReading })
	if form.standing.Text != form.m.CertificateNeedsPassphrase || form.standing.Importance == widget.DangerImportance {
		t.Errorf("without a passphrase: %q (%v), want an instruction, not an alarm", form.standing.Text, form.standing.Importance)
	}

	form.passphrase.SetText("sbagliata")
	form.readCertificate()
	settle(t, func() bool { return form.standing.Text != form.m.CertificateReading })
	if form.standing.Text != form.m.CertificateLocked || form.standing.Importance != widget.DangerImportance {
		t.Errorf("with a wrong passphrase: %q (%v)", form.standing.Text, form.standing.Importance)
	}
}

func TestAnExpiredCertificateIsSaidPlainly(t *testing.T) {
	expired := qualifiedRossi()
	expired.NotAfter = time.Now().Add(-48 * time.Hour)
	fixture := newFormFixture(t, scriptedCertificate{summary: expired})
	form := fixture.desktop.form

	form.setCertificate("/tmp/rossi.p12")
	settle(t, func() bool { return form.summary != nil })
	if form.standing.Importance != widget.DangerImportance {
		t.Errorf("an expired certificate must be shown as an error, got %q", form.standing.Text)
	}
}

func TestATimestampLevelNeedsAnAuthorityBeforeSigning(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	form.setDocument("/tmp/offerta.docx")
	form.setCertificate("/tmp/rossi.p12")

	form.level.SetSelected(form.m.LevelTimestampLabel)
	if !form.timestampBox.Visible() {
		t.Fatal("the authority field must appear with a timestamp level")
	}
	form.timestamp.SetText("")
	test.Tap(form.signButton)

	if form.status.Importance != widget.DangerImportance || len(fixture.signer.intents) != 0 {
		t.Errorf("status %q: signing must stop before the signer runs", form.status.Text)
	}
	form.level.SetSelected(form.m.LevelBasicLabel)
	if form.timestampBox.Visible() {
		t.Error("the authority field hides again at the basic level")
	}
}

func TestSigningSendsWhatTheUserSees(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	form.setDocument("/tmp/contratto.pdf")
	settle(t, func() bool { return fixture.desktop.pages.canvas != nil })
	form.setCertificate("/tmp/rossi.p12")
	form.passphrase.SetText("segreto")
	settle(t, func() bool { return form.summary != nil })

	placed := fixture.desktop.pages.canvas.Rect()
	test.Tap(form.signButton)

	intent := <-fixture.signer.intents
	if intent.Format != domain.FormatPAdES || intent.Key.Passphrase != "segreto" || intent.Location != "Roma" {
		t.Errorf("intent = %+v", intent)
	}
	if intent.Seal.Page != 1 || intent.Seal.Rect != placed {
		t.Errorf("seal = %+v, want the rectangle on the page (%+v)", intent.Seal, placed)
	}
	settle(t, func() bool { return form.afterSign.Visible() })
	if form.signedPath != "/tmp/contratto_signed.pdf" || form.status.Importance != widget.SuccessImportance {
		t.Errorf("after signing: path %q, status %q", form.signedPath, form.status.Text)
	}
}

func TestASigningFailureIsReportedInPlace(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	failing := capturingSigner{intents: make(chan domain.SigningIntent, 1), err: errors.New("timestamp: connection refused")}
	form.signing = application.NewSignFromDesktop(failing, func(string) bool { return true })
	form.setDocument("/tmp/offerta.docx")
	form.setCertificate("/tmp/rossi.p12")

	test.Tap(form.signButton)
	<-failing.intents

	settle(t, func() bool { return form.status.Importance == widget.DangerImportance })
	if form.status.Text != "timestamp: connection refused" || form.afterSign.Visible() {
		t.Errorf("status %q", form.status.Text)
	}
}

func TestTheTimestampAccountReachesTheSigner(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	form.setDocument("/tmp/offerta.docx")
	form.setCertificate("/tmp/rossi.p12")
	form.level.SetSelected(form.m.LevelTimestampLabel)
	form.timestamp.SetText("https://servizi.arubapec.it/tsa/ngrequest.php")
	form.tsaUser.SetText("studio.rossi")
	form.tsaPassword.SetText("tsa-segreta")

	test.Tap(form.signButton)
	intent := <-fixture.signer.intents

	if intent.TimestampUser != "studio.rossi" || intent.TimestampPassword != "tsa-segreta" {
		t.Errorf("account = %q / %q", intent.TimestampUser, intent.TimestampPassword)
	}
	settle(t, func() bool { return form.afterSign.Visible() })
	preferences := fyne.CurrentApp().Preferences()
	if preferences.String(preferenceTSAUser) != "studio.rossi" {
		t.Error("the TSA user must be remembered")
	}
	for _, key := range []string{preferenceCertificate, preferenceTimestamp, preferenceTSAUser, preferenceLevel} {
		if preferences.String(key) == "tsa-segreta" {
			t.Errorf("the TSA password was stored under %q", key)
		}
	}
}

type digestSigner struct{ digest string }

func (s digestSigner) Sign(_ context.Context, intent domain.SigningIntent) (domain.Receipt, error) {
	return domain.Receipt{SignedPath: intent.OutputName(), DocumentDigest: s.digest}, nil
}

func TestTheFingerprintShownIsTheOneSigned(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	document := filepath.Join(t.TempDir(), "offerta.docx")
	if err := os.WriteFile(document, []byte("offerta"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte("offerta")))

	form.setDocument(document)
	settle(t, func() bool { return form.fingerprint != "" })
	if form.fingerprint != want || !strings.Contains(form.documentRow.note.Text, want) {
		t.Fatalf("fingerprint %q, note %q; want %s shown", form.fingerprint, form.documentRow.note.Text, want)
	}

	form.setCertificate("/tmp/rossi.p12")
	form.signing = application.NewSignFromDesktop(digestSigner{digest: want}, func(string) bool { return true })
	test.Tap(form.signButton)
	settle(t, func() bool { return form.afterSign.Visible() })
	if form.status.Importance != widget.SuccessImportance {
		t.Errorf("matching fingerprints must report plain success, got %q", form.status.Text)
	}

	form.signing = application.NewSignFromDesktop(digestSigner{digest: "0000"}, func(string) bool { return true })
	test.Tap(form.signButton)
	settle(t, func() bool { return form.status.Importance == widget.WarningImportance })
	if !strings.Contains(form.status.Text, "0000") {
		t.Errorf("a changed document must be named by the fingerprint signed, got %q", form.status.Text)
	}
}

func TestAnInvisibleSignatureNeedsNoPage(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	form.setDocument("/tmp/contratto.pdf")
	settle(t, func() bool { return fixture.desktop.pages.canvas != nil })
	form.setCertificate("/tmp/rossi.p12")

	form.invisible.SetChecked(true)
	if fixture.desktop.pages.canvas != nil || form.sealNote.Text != form.m.InvisibleExplained {
		t.Fatal("an invisible signature must not offer a page to place a seal on")
	}
	test.Tap(form.signButton)
	if intent := <-fixture.signer.intents; !intent.Invisible {
		t.Errorf("intent = %+v, want an invisible signature", intent)
	}

	form.formatChoice.SetSelected(form.m.FormatCAdESLabel)
	if !form.invisible.Disabled() {
		t.Error("an envelope has no page, so the option does not apply")
	}
}

func TestAnEnvelopeOffersToAddASignature(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form

	form.setDocument("/tmp/atto.pdf.p7m")
	if form.format != domain.FormatCosign || len(form.formatChoice.Options) != 3 {
		t.Fatalf("format %s, options %v", form.format, form.formatChoice.Options)
	}
	if form.formatChoice.Options[2] != form.m.FormatWrapLabel {
		t.Errorf("the third option is %q, want the old-style envelope", form.formatChoice.Options[2])
	}
	if form.documentRow.note.Text != "Se guardará como atto.pdf_cosigned.p7m" {
		t.Errorf("note = %q", form.documentRow.note.Text)
	}
}

func TestACounterSignatureIsLabelledInTheReport(t *testing.T) {
	tab := verificationFor(t)
	tab.render(decodeReport(t, `{"signed":true,"verdict":"advanced","signers":[
		{"field":"CMS #1","signer":"MARIO ROSSI","integrity":"good"},
		{"field":"CMS #1 › countersignature 1","countersigns":"CMS #1","signer":"ANNA BIANCHI","integrity":"good"}]}`))
	if !strings.Contains(collectTexts(tab.signers), "Contrafirma de la firma CMS #1") {
		t.Error("the counter-signature must say which signature it counter-signs")
	}
}

// scriptedFields answers with the fields of a form: forms.pdf has one.
type scriptedFields struct{}

func (*scriptedFields) EmptyFields(_ context.Context, path string) ([]domain.FormField, error) {
	if !strings.HasSuffix(path, "form.pdf") {
		return nil, nil
	}
	return []domain.FormField{{Name: "Firma1", Page: 1, Rect: domain.SealRect{LowerLeftX: 300, LowerLeftY: 100, UpperRightX: 500, UpperRightY: 160}}}, nil
}

// TestAFormsFieldTakesTheSeal: a PDF with an empty signature field offers
// it; chosen, the seal sits locked in its box and the field is signed;
// back to the page, the seal moves again. A PDF without fields offers none.
func TestAFormsFieldTakesTheSeal(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	form.setDocument("/tmp/contratto.pdf")
	settle(t, func() bool { return fixture.desktop.pages.canvas != nil })
	if form.fieldBox.Visible() {
		t.Fatal("a PDF without fields offers none")
	}

	form.setDocument("/tmp/form.pdf")
	settle(t, func() bool { return form.fieldBox.Visible() })
	if want := []string{form.m.FormFieldNone, "Firma1 (página 1)"}; !reflect.DeepEqual(form.fieldChoice.Options, want) {
		t.Fatalf("options %v", form.fieldChoice.Options)
	}
	form.fieldChoice.SetSelectedIndex(1)
	settle(t, func() bool { return fixture.desktop.pages.canvas != nil && fixture.desktop.pages.canvas.locked })
	canvas := fixture.desktop.pages.canvas
	if canvas.Rect() != (domain.SealRect{LowerLeftX: 300, LowerLeftY: 100, UpperRightX: 500, UpperRightY: 160}) ||
		form.sealNote.Text != form.m.FormFieldSealHint || !fixture.desktop.pages.suggest.Disabled() {
		t.Errorf("the seal is the field's box: %+v, note %q", canvas.Rect(), form.sealNote.Text)
	}
	canvas.TypedKey(&fyne.KeyEvent{Name: fyne.KeyLeft})
	if canvas.Rect().LowerLeftX != 300 {
		t.Error("the seal in a field does not move")
	}

	form.setCertificate("/tmp/rossi.p12")
	form.passphrase.SetText("segreto")
	settle(t, func() bool { return form.summary != nil })
	test.Tap(form.signButton)
	if intent := <-fixture.signer.intents; intent.Field != "Firma1" || intent.Seal.Placed() || intent.Invisible {
		t.Errorf("intent = %+v, want the field signed", intent)
	}

	form.fieldChoice.SetSelectedIndex(0)
	settle(t, func() bool { return fixture.desktop.pages.canvas != nil && !fixture.desktop.pages.canvas.locked })
	if fixture.desktop.pages.field != nil {
		t.Error("back to the page, the seal is placed again")
	}
}

// TestAnInvoiceIsSignedAsOne: a FacturaE invoice is recognised by its
// root, offered as an invoice first, and signed with its policy and the
// role the person chooses.
func TestAnInvoiceIsSignedAsOne(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	signer := &collectingSigner{}
	form.signing = application.NewSignFromDesktop(signer, func(string) bool { return true })
	form.setCertificate("/tmp/rossi.p12")
	invoice := filepath.Join(t.TempDir(), "factura-2026-114.xml")
	if err := os.WriteFile(invoice, []byte(`<fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml"><FileHeader/></fe:Facturae>`), 0o600); err != nil {
		t.Fatal(err)
	}
	form.setDocument(invoice)
	settle(t, func() bool { return form.format == domain.FormatFacturaE })
	if !form.invoiceBox.Visible() || form.policyBox.Visible() || form.formatChoice.Options[0] != form.m.FormatFacturaELabel {
		t.Fatalf("invoice box %t, policy box %t, options %v", form.invoiceBox.Visible(), form.policyBox.Visible(), form.formatChoice.Options)
	}
	if !strings.HasPrefix(form.documentRow.note.Text, "Se guardará como factura-2026-114_signed.xml") {
		t.Errorf("note = %q", form.documentRow.note.Text)
	}
	form.invoiceRole.SetSelected(form.m.InvoiceRoleReceiver)
	test.Tap(form.signButton)
	settle(t, func() bool { signer.mu.Lock(); defer signer.mu.Unlock(); return len(signer.intents) == 1 })
	intent := signer.intents[0]
	if intent.Format != domain.FormatFacturaE || intent.Policy != domain.PolicyFacturaE || intent.Role != "receptor" {
		t.Errorf("intent %s, %s, %s", intent.Format, intent.Policy, intent.Role)
	}
}

// TestAPDFSignatureCanDeclareAPolicy: under More options, the policies a
// PDF signature can carry; an envelope offers AGE 1.8 as well, a container
// none.
func TestAPDFSignatureCanDeclareAPolicy(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	signer := &collectingSigner{}
	form.signing = application.NewSignFromDesktop(signer, func(string) bool { return true })
	form.setCertificate("/tmp/rossi.p12")
	form.setDocument("/tmp/contratto.pdf")
	if !form.policyBox.Visible() || len(form.policy.Options) != 2 || form.policy.Selected != form.m.PolicyNoneLabel {
		t.Fatalf("policies %v, chosen %q", form.policy.Options, form.policy.Selected)
	}
	form.formatChoice.SetSelected(form.m.FormatCAdESLabel)
	if len(form.policy.Options) != 3 {
		t.Errorf("an envelope declares either AGE version: %v", form.policy.Options)
	}
	form.formatChoice.SetSelected(form.m.FormatASiCSLabel)
	if form.policyBox.Visible() {
		t.Error("a container declares no policy here")
	}
	form.formatChoice.SetSelected(form.m.FormatPAdESLabel)
	form.policy.SetSelected(form.m.PolicyAGELabel)
	form.invisible.SetChecked(true)
	test.Tap(form.signButton)
	settle(t, func() bool { signer.mu.Lock(); defer signer.mu.Unlock(); return len(signer.intents) == 1 })
	if signer.intents[0].Policy != domain.PolicyAGE {
		t.Errorf("policy %q", signer.intents[0].Policy)
	}
}

// TestABatchGoesInOneASiCEContainer: the documents of a batch under one
// signature, in one command.
func TestABatchGoesInOneASiCEContainer(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	signer := &collectingSigner{}
	form.signing = application.NewSignFromDesktop(signer, func(string) bool { return true })
	form.setCertificate("/tmp/rossi.p12")
	form.setDocuments([]string{"/tmp/a.pdf", "/tmp/b.xml", "/tmp/c.dwg"})
	form.formatChoice.SetSelected(form.m.FormatASiCELabel)
	if form.format != domain.FormatASiCE || form.invisible.Disabled() == false {
		t.Fatalf("format %s, the seal choice off: %t", form.format, form.invisible.Disabled())
	}
	test.Tap(form.signButton)
	settle(t, func() bool { return strings.HasPrefix(form.status.Text, "Firmado") })
	signer.mu.Lock()
	defer signer.mu.Unlock()
	if len(signer.intents) != 1 || signer.intents[0].DocumentPath != "/tmp/a.pdf" || len(signer.intents[0].MoreDocuments) != 2 {
		t.Errorf("one command over the three documents: %+v", signer.intents)
	}
}

// TestAPDFThatOpensOnlyWithAPasswordAsksForIt: qpdf locks one with a user
// password, another with permissions only; only the first asks, and the
// password goes with the signature.
func TestAPDFThatOpensOnlyWithAPasswordAsksForIt(t *testing.T) {
	if _, err := exec.LookPath("qpdf"); err != nil {
		t.Skip("qpdf is not available")
	}
	directory := t.TempDir()
	plain := writeSampleContract(t)
	locked, permissions := filepath.Join(directory, "locked.pdf"), filepath.Join(directory, "permissions.pdf")
	for path, user := range map[string]string{locked: "abierto", permissions: ""} {
		if output, err := exec.Command("qpdf", "--encrypt", user, "propietario", "256", "--", plain, path).CombinedOutput(); err != nil {
			t.Fatalf("qpdf: %v\n%s", err, output)
		}
	}
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	form := fixture.desktop.form
	signer := &collectingSigner{}
	form.signing = application.NewSignFromDesktop(signer, func(string) bool { return true })
	form.setCertificate("/tmp/rossi.p12")

	form.setDocument(permissions)
	settle(t, func() bool { return form.fingerprint != "" })
	if form.pdfPasswordBox.Visible() {
		t.Error("a PDF that only restricts permissions opens without a password")
	}
	form.setDocument(locked)
	settle(t, func() bool { return form.pdfPasswordBox.Visible() })
	form.pdfPassword.SetText("abierto")
	form.invisible.SetChecked(true)
	test.Tap(form.signButton)
	settle(t, func() bool { signer.mu.Lock(); defer signer.mu.Unlock(); return len(signer.intents) == 1 })
	if signer.intents[0].PDFPassword != "abierto" {
		t.Errorf("password %q", signer.intents[0].PDFPassword)
	}
	form.setDocument(plain)
	if form.pdfPasswordBox.Visible() || form.pdfPassword.Text != "" {
		t.Error("another document forgets the password")
	}
}
