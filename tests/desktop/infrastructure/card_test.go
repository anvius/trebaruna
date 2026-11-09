package infrastructure_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// tokenListing is what `trebaruna token --json` prints for a DNIe-like card:
// an authentication and a signature certificate, one attempt already failed.
const tokenListing = `{"slots":[
 {"index":0,"description":"Lector 0","token":"","pin":"","pinpad":false,"certificates":[]},
 {"index":1,"description":"Lector 1","token":"DNI electrónico","pin":"count-low","pinpad":false,"certificates":[
  {"name":"MARIA GARCIA (AUTENTICACION)","identifier":"IDCES-00000000T","issuer_name":"DIRECCION GENERAL DE LA POLICIA",
   "serial":"1001","fingerprint":"40be7f7a","signs_by_default":false,"not_after":"2029-01-14T09:22:00Z",
   "trusted":true,"qualified":false,"locality":"Madrid"},
  {"name":"MARIA GARCIA (FIRMA)","identifier":"IDCES-00000000T","issuer_name":"DIRECCION GENERAL DE LA POLICIA",
   "serial":"1002","fingerprint":"a18a8855","signs_by_default":true,"not_after":"2029-01-14T09:22:00Z",
   "trusted":true,"qualified":true,"locality":"Madrid"}]}]}`

func TestTheCardsAreReadFromTheTokenListing(t *testing.T) {
	binary, recorded := fakeCommand(t, "cat <<'JSON'\n"+tokenListing+"\nJSON")

	cards, err := infrastructure.CommandLineCardReader{BinaryPath: binary}.Cards(context.Background())
	if err != nil {
		t.Fatalf("Cards: %v", err)
	}
	if arguments := recordedArguments(t, recorded); len(arguments) != 2 || arguments[0] != "token" || arguments[1] != "--json" {
		t.Errorf("arguments %v: the listing needs no PIN and no module", arguments)
	}
	if len(cards) != 2 {
		t.Fatalf("an empty reader holds no certificate; got %d certificates", len(cards))
	}
	signature := cards[1]
	if signature.Token != "DNI electrónico" || signature.Fingerprint != "a18a8855" || !signature.SignsByDefault {
		t.Errorf("signature certificate read as %+v", signature)
	}
	if signature.PIN != signing.PINCountLow || signature.Reader != "Lector 1" {
		t.Errorf("PIN state %q in %q", signature.PIN, signature.Reader)
	}
	if signature.Summary.Holder != "MARIA GARCIA (FIRMA)" || !signature.Summary.Qualified || signature.Summary.Locality != "Madrid" ||
		signature.Summary.NotAfter.Year() != 2029 {
		t.Errorf("summary %+v", signature.Summary)
	}
}

func TestACardlessBuildSaysSo(t *testing.T) {
	binary, _ := fakeCommand(t, "echo 'this build cannot use a smartcard: it was compiled without cgo' >&2; exit 2")

	_, err := infrastructure.CommandLineCardReader{BinaryPath: binary}.Cards(context.Background())
	if err == nil || err.Error() != "this build cannot use a smartcard: it was compiled without cgo" {
		t.Errorf("the command's explanation must reach the window, got %v", err)
	}
}

func cardSigningIntent() domain.SigningIntent {
	intent := fullIntent()
	intent.Key = domain.CertificateFile{}
	intent.Card = domain.CardKey{Token: "DNI electrónico", Fingerprint: "a18a8855", PIN: "123456", State: signing.PINReady}
	return intent
}

func TestACardSignsTheCertificateChosenWithThePINInTheEnvironment(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "environment")
	binary, recorded := fakeCommand(t, "printf '%s' \"$TREBARUNA_PIN\" > "+seen+"; echo '"+receiptJSON+"'")

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), cardSigningIntent()); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	arguments := recordedArguments(t, recorded)
	if !containsPair(arguments, "--token", "DNI electrónico") || !containsPair(arguments, "--certificate", "a18a8855") {
		t.Errorf("the card and its certificate must be named: %v", arguments)
	}
	for _, argument := range arguments {
		if argument == "--p12" || argument == "--pin" || argument == "123456" {
			t.Fatalf("a file flag or the PIN reached the command line: %v", arguments)
		}
	}
	if got, _ := os.ReadFile(seen); string(got) != "123456" {
		t.Errorf("TREBARUNA_PIN = %q, want the PIN", got)
	}
}

func TestTheCardsRefusalsBecomeProblems(t *testing.T) {
	cases := []struct {
		stderr string
		code   domain.ProblemCode
		detail string
	}{
		{`signing failed: read the signing certificate: the card refused the PIN (token "DNI electrónico")`, domain.ProblemWrongPIN, ""},
		{`signing failed: the card refused the PIN (token "X"): one more wrong PIN locks the card`, domain.ProblemWrongPIN, string(signing.PINFinalTry)},
		{`signing failed: the card refused the PIN (token "X"): the card is locked: unlock it with its PUK`, domain.ProblemWrongPIN, string(signing.PINLocked)},
		{`signing failed: the card is locked: unlock it with its PUK (token "X")`, domain.ProblemCardLocked, ""},
		{`signing failed: the card asks for its PIN to be changed before it signs (token "X")`, domain.ProblemPINExpired, ""},
		{`signing failed: the card needs its PIN (token "X"): give it in $TREBARUNA_PIN`, domain.ProblemMissingPIN, ""},
	}
	for _, entry := range cases {
		binary, _ := fakeCommand(t, "echo '"+entry.stderr+"' >&2; exit 1")
		_, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), cardSigningIntent())
		var problem domain.Problem
		if !errors.As(err, &problem) || problem.Code != entry.code || problem.Detail != entry.detail {
			t.Errorf("%q became %v, want %s/%s", entry.stderr, err, entry.code, entry.detail)
		}
	}
}

func TestTheFirefoxStoreIsListedAndSignedWithItsOwnFlag(t *testing.T) {
	binary, recorded := fakeCommand(t, "cat <<'JSON'\n"+tokenListing+"\nJSON")
	cards, err := infrastructure.CommandLineCardReader{BinaryPath: binary, Store: domain.StoreFirefox}.Cards(context.Background())
	if err != nil {
		t.Fatalf("Cards: %v", err)
	}
	if arguments := recordedArguments(t, recorded); !contains(arguments, "--firefox") {
		t.Errorf("arguments %v: the store must be asked for", arguments)
	}
	if cards[0].Store != domain.StoreFirefox {
		t.Errorf("store %q", cards[0].Store)
	}

	binary, recorded = fakeCommand(t, "echo '"+receiptJSON+"'")
	intent := cardSigningIntent()
	intent.Card.Store = domain.StoreFirefox
	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	arguments := recordedArguments(t, recorded)
	if !contains(arguments, "--firefox") || !containsPair(arguments, "--certificate", "a18a8855") || contains(arguments, "--token") {
		t.Errorf("arguments %v: the store is named by --firefox, not by a card label", arguments)
	}
}

func TestAPINChangeRunsTheCommandWithItsSecretsInTheEnvironment(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "environment")
	binary, recorded := fakeCommand(t, "printf '%s %s' \"$TREBARUNA_PUK\" \"$TREBARUNA_NEW_PIN\" > "+seen+"; echo '{\"changed\":true}'")

	change := domain.PINChange{Action: domain.UnlockPIN, Token: "Carta Nazionale", Secret: "87654321", NewPIN: "2468", Repeat: "2468"}
	if err := (infrastructure.CommandLinePINChanger{BinaryPath: binary}).Apply(context.Background(), change); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	arguments := recordedArguments(t, recorded)
	if arguments[0] != "pin" || arguments[1] != "unlock" || !containsPair(arguments, "--token", "Carta Nazionale") {
		t.Errorf("arguments %v", arguments)
	}
	for _, argument := range arguments {
		if argument == "87654321" || argument == "2468" {
			t.Fatalf("a secret reached the command line: %v", arguments)
		}
	}
	if got, _ := os.ReadFile(seen); string(got) != "87654321 2468" {
		t.Errorf("environment carried %q", got)
	}
}

func TestTheCardsAnswersToAPINChangeBecomeProblems(t *testing.T) {
	cases := []struct {
		stderr string
		code   domain.ProblemCode
		detail string
	}{
		{`the card refused the PUK (token "X"): one more wrong PIN locks the card`, domain.ProblemWrongPUK, string(signing.PINFinalTry)},
		{`the card refused the PUK (token "X"): the card's PUK is locked: only its issuer can unlock it`, domain.ProblemWrongPUK, string(signing.PINLocked)},
		{`the card's PUK is locked: only its issuer can unlock it (token "X")`, domain.ProblemPUKLocked, ""},
		{`the new PIN does not fit the card: it has 2 characters, the card wants at least 4 (token "X")`, domain.ProblemNewPINRejected, "min:4"},
		{`the new PIN does not fit the card: it has 12 characters, the card takes at most 8 (token "X")`, domain.ProblemNewPINRejected, "max:8"},
		{`the card refused the PIN (token "X")`, domain.ProblemWrongPIN, ""},
		{`the card is locked: unlock it with its PUK (token "X")`, domain.ProblemCardLocked, ""},
	}
	for _, entry := range cases {
		binary, _ := fakeCommand(t, "echo '"+strings.ReplaceAll(entry.stderr, "'", "'\\''")+"' >&2; exit 1")
		err := (infrastructure.CommandLinePINChanger{BinaryPath: binary}).Apply(context.Background(),
			domain.PINChange{Action: domain.ChangePIN, Secret: "1", NewPIN: "2", Repeat: "2"})
		var problem domain.Problem
		if !errors.As(err, &problem) || problem.Code != entry.code || problem.Detail != entry.detail {
			t.Errorf("%q became %v, want %s/%s", entry.stderr, err, entry.code, entry.detail)
		}
	}
}
