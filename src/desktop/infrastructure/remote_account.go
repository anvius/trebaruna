//go:build gui

package infrastructure

import (
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/messaging"
)

const (
	preferenceRemoteAddress = "remote.address"
	preferenceRemoteUser    = "remote.user"
	preferenceRemoteClient  = "remote.client"
)

// remoteAccount is the part of step 2 that reaches a remote signing
// service: its address and how to sign in. The service's credentials are
// then listed below it as a card's certificates. The address, the user and
// the client id are remembered; the password and the one-time code are not.
type remoteAccount struct {
	address, user, password, client, otp *widget.Entry
	root                                 *fyne.Container

	// current is what the fields say, kept on the UI thread for the
	// listing, which reads it from another goroutine.
	mutex   sync.Mutex
	current domain.RemoteAccount
}

func newRemoteAccount(m messaging.Catalogue, preferences fyne.Preferences) *remoteAccount {
	r := &remoteAccount{
		address: widget.NewEntry(), user: widget.NewEntry(), password: widget.NewPasswordEntry(),
		client: widget.NewEntry(), otp: widget.NewPasswordEntry(),
	}
	r.address.SetPlaceHolder("https://…/csc/v2")
	r.address.SetText(preferences.String(preferenceRemoteAddress))
	r.user.SetText(preferences.String(preferenceRemoteUser))
	r.client.SetText(preferences.String(preferenceRemoteClient))
	for _, entry := range []*widget.Entry{r.address, r.user, r.password, r.client, r.otp} {
		entry.OnChanged = func(string) { r.update(preferences) }
	}
	r.update(preferences)

	r.root = container.NewVBox(
		fieldLabel(m.RemoteAddressLabel), r.address,
		container.NewGridWithColumns(2,
			container.NewVBox(fieldLabel(m.RemoteUserLabel), r.user),
			container.NewVBox(fieldLabel(m.RemotePasswordLabel), r.password)),
		fieldLabel(m.RemoteClientLabel), r.client,
		caption(m.RemoteAccountHint),
		fieldLabel(m.RemoteOTPLabel), r.otp,
	)
	return r
}

func (r *remoteAccount) object() fyne.CanvasObject { return r.root }

// update takes what the fields say and remembers what may be remembered.
func (r *remoteAccount) update(preferences fyne.Preferences) {
	account := domain.RemoteAccount{
		Address: strings.TrimSpace(r.address.Text), User: strings.TrimSpace(r.user.Text), Password: r.password.Text,
		OAuthClient: strings.TrimSpace(r.client.Text), OTP: r.otp.Text,
	}
	preferences.SetString(preferenceRemoteAddress, account.Address)
	preferences.SetString(preferenceRemoteUser, account.User)
	preferences.SetString(preferenceRemoteClient, account.OAuthClient)
	r.mutex.Lock()
	r.current = account
	r.mutex.Unlock()
}

// account is how to reach the service, as the fields last said.
func (r *remoteAccount) account() domain.RemoteAccount {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.current
}
