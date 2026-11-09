//go:build cgo

package infrastructure_test

// The PIN, checked against SoftHSM. A real card allows three attempts or so
// before it locks, and unlocking it takes the PUK the person rarely has at
// hand, so no attempt may be spent where it can be avoided.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// TestAWrongPINIsNamedAsSuch: the card's CKR_PIN_INCORRECT becomes the
// business error, so the window and a batch can stop on it.
func TestAWrongPINIsNamedAsSuch(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	_, err := loadFromCard(t, token.module, token.label, "0000", domain.ChooseCertificateBy(""))
	if !errors.Is(err, domain.ErrWrongPIN) {
		t.Fatalf("a wrong PIN must be reported as one, got %v", err)
	}
}

// TestAnEmptyPINIsNotTried: an empty PIN is a wrong PIN to the card, which
// would count it.
func TestAnEmptyPINIsNotTried(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	_, err := loadFromCard(t, token.module, token.label, "", domain.ChooseCertificateBy(""))
	if !errors.Is(err, domain.ErrPINMissing) {
		t.Fatalf("an empty PIN must be refused before the card sees it, got %v", err)
	}
	if !strings.Contains(err.Error(), "TREBARUNA_PIN") {
		t.Errorf("the error must say where the PIN goes: %v", err)
	}
}

// TestABatchStopsAtTheFirstRefusedPIN: signing ten documents with a wrong PIN
// must not try it ten times.
func TestABatchStopsAtTheFirstRefusedPIN(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	directory := t.TempDir()
	var documents []string
	for _, name := range []string{"uno.txt", "due.txt", "tre.txt"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatalf("write document: %v", err)
		}
		documents = append(documents, path)
	}
	t.Setenv("TREBARUNA_PIN", "0000")

	var stdout, stderr bytes.Buffer
	arguments := append([]string{"sign"}, documents...)
	arguments = append(arguments, "--format", "cades", "--module", token.module, "--token", token.label, "--json")
	if code := cli.Run(arguments, &stdout, &stderr); code == 0 {
		t.Fatal("a batch with a wrong PIN must not succeed")
	}

	var report struct {
		Failed  int `json:"failed"`
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("batch report: %v\n%s", err, stdout.String())
	}
	if report.Failed != 3 || len(report.Results) != 3 {
		t.Fatalf("three documents must be reported as failed: %+v", report)
	}
	if !strings.Contains(report.Results[0].Error, domain.ErrWrongPIN.Error()) {
		t.Errorf("the first document must carry the refusal: %q", report.Results[0].Error)
	}
	for _, result := range report.Results[1:] {
		if !strings.HasPrefix(result.Error, "not tried") {
			t.Errorf("a later document must not be tried: %q", result.Error)
		}
	}
}

// TestTwoCardsWithTheSameLabelAreToldApart: two identity cards are both
// labelled the same; the certificate says which one signs.
func TestTwoCardsWithTheSameLabelAreToldApart(t *testing.T) {
	label := "DNI electronico"
	first := startSoftHSMLabelled(t, label)
	second := startSoftHSMLabelled(t, label)
	var wanted []byte
	for index, token := range []softHSM{first, second} {
		token.keyPair(t, "01", "signature")
		issued := issueCertificateWithUsage(t, token, "01", "nonRepudiation")
		if issued == nil {
			t.Skip("openssl is not available to issue a certificate")
		}
		importCertificate(t, token, "01", "signature", issued)
		if index == 1 {
			wanted = issued
		}
	}
	certificate := parsePEMCertificate(t, wanted)

	pair, err := loadFromCard(t, first.module, label, first.pin, domain.ChooseCertificateBy(domain.Fingerprint(certificate)))
	if err != nil {
		t.Fatalf("load from the second card: %v", err)
	}
	if !pair.Certificate.Equal(certificate) {
		t.Errorf("signed with serial %s, want %s", pair.Certificate.SerialNumber.Text(16), certificate.SerialNumber.Text(16))
	}

	_, err = loadFromCard(t, first.module, label, first.pin, domain.ChooseCertificateBy(""))
	if err == nil || !strings.Contains(err.Error(), "several cards") {
		t.Errorf("two cards with one label and no certificate named must not be guessed, got %v", err)
	}
}

// TestTheTokenListingCarriesWhatTheWindowShows: the desktop reads the PIN
// state and the certificate's identity and standing from `token --json`.
func TestTheTokenListingCarriesWhatTheWindowShows(t *testing.T) {
	token, _, signature := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"token", "--module", token.module, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("token exited %d: %s", code, stderr.String())
	}
	var listing struct {
		Slots []struct {
			Token        string `json:"token"`
			PIN          string `json:"pin"`
			Certificates []struct {
				Name           string `json:"name"`
				Fingerprint    string `json:"fingerprint"`
				SignsByDefault bool   `json:"signs_by_default"`
				IssuerName     string `json:"issuer_name"`
				NotAfter       string `json:"not_after"`
			} `json:"certificates"`
		} `json:"slots"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &listing); err != nil {
		t.Fatalf("token --json: %v\n%s", err, stdout.String())
	}
	for _, slot := range listing.Slots {
		if slot.Token != token.label {
			continue
		}
		if slot.PIN != string(domain.PINReady) {
			t.Errorf("pin state %q, want %q", slot.PIN, domain.PINReady)
		}
		for _, certificate := range slot.Certificates {
			if certificate.Name != "Token Test Signer" || certificate.IssuerName != "Token Test CA" || certificate.NotAfter == "" {
				t.Errorf("incomplete certificate entry: %+v", certificate)
			}
			if certificate.SignsByDefault != (certificate.Fingerprint == domain.Fingerprint(signature)) {
				t.Errorf("signs_by_default wrong for %s", certificate.Fingerprint)
			}
		}
		return
	}
	t.Fatalf("token %q not listed:\n%s", token.label, stdout.String())
}

// TestAnOpenSessionNeverVouchesForAnotherPIN: a PKCS#11 login belongs to the
// whole process. While one signature held a logged-in session, a second
// login answered "already logged in" and a wrong PIN signed. Now the second
// waits for the first and the card checks its PIN.
func TestAnOpenSessionNeverVouchesForAnotherPIN(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")
	signer := func(pin string) domain.Signer {
		built, err := domain.NewSigner(domain.NameFromCertificate, domain.FromToken, domain.WithToken(token.module, token.label, pin))
		if err != nil {
			t.Fatal(err)
		}
		return built
	}

	open, err := infrastructure.LoadKeyPair(signer(token.pin))
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		pair, err := infrastructure.LoadKeyPair(signer("0000"))
		if err == nil {
			_ = pair.Close()
		}
		result <- err
	}()

	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-result:
		t.Fatalf("the second session ran while the first was open: %v", err)
	default:
	}
	_ = open.Close()

	if err := <-result; !errors.Is(err, domain.ErrWrongPIN) {
		t.Fatalf("a wrong PIN must be refused even right after a good one, got %v", err)
	}
}
