package infrastructure_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	"codeberg.org/simplicer/trebaruna/src/desktop/infrastructure"
)

const certificateJSON = `{"path":"/tmp/m.p12","certificates":[{"name":"MARIO ROSSI","identifier":"TINIT-RSSMRA80A01H501U",` +
	`"issuer_name":"InfoCert S.p.A.","not_after":"2028-03-12T00:00:00Z","self_signed":false,"trusted":true,` +
	`"qualified":true,"locality":"Roma"},{"name":"InfoCert CA"}]}`

func TestTheCertificateIsDescribedFromTheCommand(t *testing.T) {
	binary, recorded := fakeCommand(t, "echo '"+certificateJSON+"'")

	summary, err := (infrastructure.CommandLineCertificateReader{BinaryPath: binary}).Read(
		context.Background(), domain.CertificateFile{Path: "/tmp/m.p12", Passphrase: "segreto"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	want := domain.CertificateSummary{
		Holder: "MARIO ROSSI", Identifier: "TINIT-RSSMRA80A01H501U", Issuer: "InfoCert S.p.A.",
		NotAfter: time.Date(2028, 3, 12, 0, 0, 0, 0, time.UTC), Trusted: true, Qualified: true, Locality: "Roma",
	}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
	arguments := recordedArguments(t, recorded)
	if strings.Join(arguments, " ") != "certificate /tmp/m.p12 --json" {
		t.Errorf("arguments = %v, the passphrase must not be among them", arguments)
	}
}

func TestTheReaderHandsThePassphraseOverTheEnvironment(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "environment")
	binary, _ := fakeCommand(t, "printf '%s' \"$TREBARUNA_PASSPHRASE\" > "+seen+"; echo '"+certificateJSON+"'")

	if _, err := (infrastructure.CommandLineCertificateReader{BinaryPath: binary}).Read(
		context.Background(), domain.CertificateFile{Path: "/tmp/m.p12", Passphrase: "segreto"}); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got, _ := os.ReadFile(seen); string(got) != "segreto" {
		t.Errorf("TREBARUNA_PASSPHRASE = %q", got)
	}
}

func TestAWrongPassphraseIsALockedCertificate(t *testing.T) {
	binary, _ := fakeCommand(t, "echo 'the passphrase does not open \"/tmp/m.p12\"' >&2; exit 2")

	_, err := (infrastructure.CommandLineCertificateReader{BinaryPath: binary}).Read(
		context.Background(), domain.CertificateFile{Path: "/tmp/m.p12"})

	var problem domain.Problem
	if !errors.As(err, &problem) || problem.Code != domain.ProblemLockedCertificate {
		t.Fatalf("err = %v, want ProblemLockedCertificate", err)
	}
}

func TestOtherReaderFailuresKeepTheirWords(t *testing.T) {
	cases := map[string]string{
		"echo 'read \"/tmp/x\": no such file' >&2; exit 2": "no such file",
		"echo 'not json'":              "unreadable",
		"echo '{\"certificates\":[]}'": "no certificate",
		"echo '{\"certificates\":[{\"name\":\"X\",\"not_after\":\"soon\"}]}'": "unreadable expiry",
	}
	for body, want := range cases {
		binary, _ := fakeCommand(t, body)
		_, err := (infrastructure.CommandLineCertificateReader{BinaryPath: binary}).Read(
			context.Background(), domain.CertificateFile{Path: "/tmp/x"})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want it to mention %q", body, err, want)
		}
	}
}

func TestASignatureWithAWrongPassphraseIsALockedCertificate(t *testing.T) {
	binary, _ := fakeCommand(t, "echo 'signing failed: decode p12 \"/tmp/m.p12\": pkcs12: decryption password incorrect' >&2; exit 1")

	_, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), fullIntent())

	var problem domain.Problem
	if !errors.As(err, &problem) || problem.Code != domain.ProblemLockedCertificate {
		t.Fatalf("err = %v, want ProblemLockedCertificate", err)
	}
}

func TestLongTermLevelsMayAskForRevocation(t *testing.T) {
	binary, recorded := fakeCommand(t, "echo '"+receiptJSON+"'")
	intent := fullIntent()
	intent.Level = domain.LevelArchive

	if _, err := (infrastructure.CommandLineSigner{BinaryPath: binary}).Sign(context.Background(), intent); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !contains(recordedArguments(t, recorded), "--online-revocation") {
		t.Error("LTA embeds revocation evidence, so the command must be allowed to fetch it")
	}
}
