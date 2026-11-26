package infrastructure_test

import (
	"context"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"
)

// TestTheStoreCertificateNamesItsBrowser: the listing carries the browser the
// store belongs to, so the window can name the primary password after it; a
// card's certificates name no browser.
func TestTheStoreCertificateNamesItsBrowser(t *testing.T) {
	const store = `{"browser":"LibreWolf","slots":[{"description":"NSS Certificate DB","token":"NSS Certificate DB",` +
		`"pin":"not-required","certificates":[{"name":"FIXTURE HOLDER","fingerprint":"ab12","serial":"01",` +
		`"signs_by_default":true,"not_after":"2030-01-01T00:00:00Z"}]}]}`
	binary, _ := fakeCommand(t, "echo '"+store+"'")
	cards, err := infrastructure.CommandLineCardReader{BinaryPath: binary, Store: domain.StoreFirefox}.Cards(context.Background())
	if err != nil {
		t.Fatalf("Cards: %v", err)
	}
	if len(cards) != 1 || cards[0].Browser != "LibreWolf" || cards[0].Store != domain.StoreFirefox {
		t.Errorf("cards %+v: the store's certificate must name LibreWolf", cards)
	}

	const card = `{"slots":[{"description":"Reader","token":"CARD","pin":"not-required","certificates":[{"name":"FIXTURE",` +
		`"fingerprint":"cd34","serial":"02","not_after":"2030-01-01T00:00:00Z"}]}]}`
	binary, _ = fakeCommand(t, "echo '"+card+"'")
	cards, err = infrastructure.CommandLineCardReader{BinaryPath: binary}.Cards(context.Background())
	if err != nil {
		t.Fatalf("Cards: %v", err)
	}
	if len(cards) != 1 || cards[0].Browser != "" {
		t.Errorf("a card's certificate named %q", cards[0].Browser)
	}
}
