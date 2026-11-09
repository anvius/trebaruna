//go:build gui

package infrastructure

import (
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// remoteCredentials is a provider holding one explicit credential.
func remoteCredentials() []domain.CardCertificate {
	return []domain.CardCertificate{{Token: "provider.example", Reader: "firma-qualificata", PIN: signing.PINReady,
		Fingerprint: "bf00", SignsByDefault: true, Store: domain.StoreRemote, Credential: "firma-qualificata",
		Summary: domain.CertificateSummary{Holder: "MARIO ROSSI", Issuer: "Provider CA", NotAfter: time.Now().Add(400 * 24 * time.Hour),
			Trusted: true, Qualified: true}}}
}

// TestARemoteServiceSignsWithTheCredentialChosen: the service's account
// replaces the file half, its credentials are chosen as a card's
// certificates, and the signature carries the credential, the account and
// the PIN; the address, the user and the client id are remembered, the
// password and the code are not.
func TestARemoteServiceSignsWithTheCredentialChosen(t *testing.T) {
	fixture := newFormFixtureWithCards(t, scriptedCertificate{summary: qualifiedRossi()}, &scriptedCards{})
	form := fixture.desktop.form
	remote := &scriptedCards{listings: [][]domain.CardCertificate{remoteCredentials()}}
	form.remoteList = application.NewListCards(remote)
	form.setDocument("/tmp/offerta.docx")

	form.keySource.SetSelected(form.m.KeyFromRemote)
	if !form.remote.object().Visible() || form.fileSource.Visible() || form.cards.search.Text != form.m.SearchRemote {
		t.Fatal("the remote account must replace the file half, with its own search")
	}
	form.remote.address.SetText("https://provider.example/csc/v2")
	form.remote.user.SetText("mario")
	form.remote.password.SetText("segreto")
	form.remote.client.SetText("trebaruna-client")
	form.remote.otp.SetText("778899")
	test.Tap(form.cards.search)
	settle(t, func() bool { return form.summary != nil })
	if form.holder.Text != "MARIO ROSSI" || !strings.Contains(form.cards.where.Text, "provider.example") {
		t.Errorf("holder %q, where %q", form.holder.Text, form.cards.where.Text)
	}

	form.cards.pin.SetText("123456")
	test.Tap(form.signButton)
	var intent domain.SigningIntent
	select {
	case intent = <-fixture.signer.intents:
	case <-time.After(5 * time.Second):
		t.Fatalf("nothing was signed: %q", form.status.Text)
	}
	settle(t, func() bool { return form.afterSign.Visible() })
	want := domain.RemoteAccount{Address: "https://provider.example/csc/v2", User: "mario", Password: "segreto",
		OAuthClient: "trebaruna-client", OTP: "778899"}
	if intent.Card.Store != domain.StoreRemote || intent.Card.Credential != "firma-qualificata" || intent.Card.PIN != "123456" ||
		intent.Card.Account != want {
		t.Errorf("remote key %+v", intent.Card)
	}

	preferences := fyne.CurrentApp().Preferences()
	if preferences.String(preferenceKeySource) != domain.StoreRemote || preferences.String(preferenceRemoteAddress) != want.Address ||
		preferences.String(preferenceRemoteUser) != "mario" || preferences.String(preferenceRemoteClient) != "trebaruna-client" {
		t.Error("the service, its user and client id are remembered")
	}
	for _, key := range []string{"remote.password", "remote.otp"} {
		if preferences.String(key) != "" {
			t.Errorf("%s was remembered", key)
		}
	}

	// Back to a file: the account goes away.
	form.keySource.SetSelected(form.m.KeyFromFile)
	if form.remote.object().Visible() || form.cards.object().Visible() {
		t.Error("the remote account stays with a file")
	}
}
