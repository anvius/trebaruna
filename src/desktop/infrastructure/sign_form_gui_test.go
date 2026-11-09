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
	"path/filepath"
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
	test.NewTempApp(t)
	// As main.go does before any widget exists.
	InstallTranslations(messaging.Spanish)
	window := test.NewTempWindow(t, nil)
	signer := capturingSigner{intents: make(chan domain.SigningIntent, 1)}

	desktop := newDesktop(window, messaging.For(messaging.Spanish), "trebaruna")
	desktop.application = application.NewSignFromDesktop(signer, func(string) bool { return true })
	desktop.inspect = application.NewInspectCertificate(reader)
	desktop.preview = application.NewPreviewPage(blankRenderer{}, application.InkFinder{})
	window.SetContent(desktop.withTabs(desktop.buildContent("")))
	window.Resize(fyne.NewSize(1220, 800))
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

	if len(form.formatChoice.Options) != 3 || form.format != domain.FormatPAdES {
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

	form.setDocument("/tmp/offerta.docx")

	if form.format != domain.FormatCAdES || len(form.formatChoice.Options) != 2 {
		t.Fatalf("format %s, options %v: a .docx goes in an envelope or gets a .p7s beside it", form.format, form.formatChoice.Options)
	}
	form.formatChoice.SetSelected(form.m.FormatDetachedLabel)
	if form.format != domain.FormatCAdESDetached || form.documentRow.note.Text != "Se guardará como offerta.docx.p7s" {
		t.Errorf("format %s, note %q", form.format, form.documentRow.note.Text)
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
