package infrastructure_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"
)

// remoteListing is what `trebaruna token --csc … --json` prints for a
// service holding one explicit credential.
const remoteListing = `{"slots":[{"index":0,"description":"firma-qualificata","token":"provider.example","login":"remote",
"pin":"ready","pinpad":false,"certificates":[{"name":"MARIO ROSSI","issuer_name":"Provider CA","serial":"2",
"fingerprint":"bf00","signs_by_default":true,"not_after":"2030-01-01T00:00:00Z","credential":"firma-qualificata"}]}]}`

// TestARemoteServicesCredentialsAreListedAsCertificates: the service's
// address and the client id go on the command line, the user and password
// in the environment; each credential comes back as a certificate.
func TestARemoteServicesCredentialsAreListedAsCertificates(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "environment")
	binary, recorded := fakeCommand(t, `printf '%s|%s' "$TREBARUNA_CSC_USER" "$TREBARUNA_CSC_PASSWORD" > `+seen+`; echo '`+remoteListing+`'`)
	account := domain.RemoteAccount{Address: "https://provider.example/csc/v2", User: "mario", Password: "segreto", OAuthClient: "trebaruna"}
	reader := infrastructure.CommandLineCardReader{BinaryPath: binary, Store: domain.StoreRemote,
		Account: func() domain.RemoteAccount { return account }}

	certificates, err := reader.Cards(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	arguments := recordedArguments(t, recorded)
	if !containsPair(arguments, "--csc", account.Address) || !containsPair(arguments, "--csc-client", "trebaruna") ||
		contains(arguments, "segreto") || contains(arguments, "mario") {
		t.Errorf("arguments: %v", arguments)
	}
	if got, _ := os.ReadFile(seen); string(got) != "mario|segreto" {
		t.Errorf("environment: %q", got)
	}
	if len(certificates) != 1 || certificates[0].Credential != "firma-qualificata" || certificates[0].Store != domain.StoreRemote ||
		certificates[0].Summary.Holder != "MARIO ROSSI" {
		t.Fatalf("certificates: %+v", certificates)
	}

	// Without an address there is nothing to ask.
	account.Address = ""
	before, _ := os.ReadFile(recorded)
	if listed, err := reader.Cards(context.Background()); err != nil || len(listed) != 0 {
		t.Errorf("without an address: %v, %v", listed, err)
	}
	if after, _ := os.ReadFile(recorded); string(after) != string(before) {
		t.Error("the command ran without an address")
	}
}

// TestARemoteKeySignsThroughItsService: the credential chosen, the
// service and the client id on the command line; the account's secrets,
// the PIN and the one-time code in the environment.
func TestARemoteKeySignsThroughItsService(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "environment")
	binary, recorded := fakeCommand(t, `printf '%s|%s|%s|%s' "$TREBARUNA_CSC_USER" "$TREBARUNA_CSC_PASSWORD" "$TREBARUNA_PIN" "$TREBARUNA_OTP" > `+
		seen+`; echo '`+receiptJSON+`'`)
	intent := fullIntent()
	intent.Key = domain.CertificateFile{}
	intent.Card = domain.CardKey{Token: "provider.example", Fingerprint: "bf00", PIN: "123456", Store: domain.StoreRemote,
		Credential: "firma-qualificata",
		Account:    domain.RemoteAccount{Address: "https://provider.example/csc/v2", User: "mario", Password: "segreto", OTP: "778899"}}

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	arguments := recordedArguments(t, recorded)
	if !containsPair(arguments, "--csc", "https://provider.example/csc/v2") || !containsPair(arguments, "--credential", "firma-qualificata") ||
		contains(arguments, "--p12") || contains(arguments, "--token") || contains(arguments, "--csc-client") {
		t.Errorf("arguments: %v", arguments)
	}
	for _, secret := range []string{"segreto", "123456", "778899"} {
		if strings.Contains(strings.Join(arguments, " "), secret) {
			t.Errorf("%s reached the command line", secret)
		}
	}
	if got, _ := os.ReadFile(seen); string(got) != "mario|segreto|123456|778899" {
		t.Errorf("environment: %q", got)
	}
}
