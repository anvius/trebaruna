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

// TestADocumentIsEncryptedForEachRecipient: one --to per certificate, and
// the envelope and the names the command printed come back.
func TestADocumentIsEncryptedForEachRecipient(t *testing.T) {
	binary, recorded := fakeCommand(t, `echo '{"path":"/tmp/offerta.pdf.p7e","size":4096,"recipients":["ANNA BIANCHI","LUCA VERDI"]}'`)

	sealed, err := infrastructure.CommandLineEncrypter{BinaryPath: binary}.Encrypt(context.Background(), domain.EncryptionIntent{
		DocumentPath: "/tmp/offerta.pdf", Recipients: []string{"/tmp/anna.pem", "/tmp/luca.cer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	arguments := recordedArguments(t, recorded)
	if arguments[0] != "encrypt" || arguments[1] != "/tmp/offerta.pdf" || !contains(arguments, "--json") ||
		!containsPair(arguments, "--to", "/tmp/anna.pem") || !containsPair(arguments, "--to", "/tmp/luca.cer") {
		t.Errorf("arguments: %v", arguments)
	}
	if sealed.Path != "/tmp/offerta.pdf.p7e" || strings.Join(sealed.Recipients, "|") != "ANNA BIANCHI|LUCA VERDI" {
		t.Errorf("sealed: %+v", sealed)
	}

	failing, _ := fakeCommand(t, "echo '/tmp/luca.cer is not a certificate' >&2; exit 2")
	if _, err := (infrastructure.CommandLineEncrypter{BinaryPath: failing}).Encrypt(context.Background(), domain.EncryptionIntent{
		DocumentPath: "/tmp/offerta.pdf", Recipients: []string{"/tmp/luca.cer"},
	}); err == nil || !strings.Contains(err.Error(), "is not a certificate") {
		t.Errorf("the command's explanation is lost: %v", err)
	}
}

// TestAnEnvelopeOpensWithTheKeyChosenToSign: the key's flags are the
// signing ones, and the passphrase and the PIN travel in the environment.
func TestAnEnvelopeOpensWithTheKeyChosenToSign(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "environment")
	binary, recorded := fakeCommand(t, `printf '%s|%s' "$TREBARUNA_PASSPHRASE" "$TREBARUNA_PIN" > `+seen+
		`; echo '{"path":"/tmp/offerta.pdf","size":2048}'`)

	opener := infrastructure.CommandLineEnvelopeOpener{BinaryPath: binary}
	opened, err := opener.Open(context.Background(), domain.OpeningIntent{
		EnvelopePath: "/tmp/offerta.pdf.p7e", Key: domain.CertificateFile{Path: "/tmp/mario.p12", Passphrase: "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	arguments := recordedArguments(t, recorded)
	if arguments[0] != "decrypt" || arguments[1] != "/tmp/offerta.pdf.p7e" || !containsPair(arguments, "--p12", "/tmp/mario.p12") {
		t.Errorf("arguments: %v", arguments)
	}
	if contains(arguments, "secret") || contains(arguments, "--pass") {
		t.Fatalf("the passphrase leaked into the command line: %v", arguments)
	}
	if got, _ := os.ReadFile(seen); string(got) != "secret|" {
		t.Errorf("environment: %q", got)
	}
	if opened.Path != "/tmp/offerta.pdf" || opened.Size != 2048 {
		t.Errorf("opened: %+v", opened)
	}

	// A card: its token and certificate, the PIN in the environment.
	if _, err := opener.Open(context.Background(), domain.OpeningIntent{
		EnvelopePath: "/tmp/offerta.pdf.p7e", Card: domain.CardKey{Token: "DNI electrónico", Fingerprint: "ab12", PIN: "1234"},
	}); err != nil {
		t.Fatal(err)
	}
	arguments = recordedArguments(t, recorded)
	if !containsPair(arguments, "--token", "DNI electrónico") || !containsPair(arguments, "--certificate", "ab12") || contains(arguments, "1234") {
		t.Errorf("card arguments: %v", arguments)
	}
	if got, _ := os.ReadFile(seen); string(got) != "|1234" {
		t.Errorf("environment: %q", got)
	}
}

// TestARefusedKeyIsExplained: a passphrase that does not open the file and
// a PIN the card refused are the problems the window explains, as when
// signing.
func TestARefusedKeyIsExplained(t *testing.T) {
	intent := domain.OpeningIntent{EnvelopePath: "/tmp/offerta.pdf.p7e", Key: domain.CertificateFile{Path: "/tmp/mario.p12"}}
	for stderr, want := range map[string]domain.ProblemCode{
		"pkcs12: decryption password incorrect": domain.ProblemLockedCertificate,
		signing.ErrWrongPIN.Error():             domain.ProblemWrongPIN,
		signing.ErrCardLocked.Error():           domain.ProblemCardLocked,
	} {
		binary, _ := fakeCommand(t, "echo '"+stderr+"' >&2; exit 2")
		_, err := infrastructure.CommandLineEnvelopeOpener{BinaryPath: binary}.Open(context.Background(), intent)
		var problem domain.Problem
		if !errors.As(err, &problem) || problem.Code != want {
			t.Errorf("%q: %v, want %s", stderr, err, want)
		}
	}
	binary, _ := fakeCommand(t, "echo 'none of the envelope'\"'\"'s recipients is this certificate' >&2; exit 3")
	if _, err := (infrastructure.CommandLineEnvelopeOpener{BinaryPath: binary}).Open(context.Background(), intent); err == nil ||
		!strings.Contains(err.Error(), "recipients is this certificate") {
		t.Errorf("the command's explanation is lost: %v", err)
	}
}
