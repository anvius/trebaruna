//go:build cgo

package infrastructure_test

// Choosing the certificate of a card, checked against SoftHSM.
//
// A real signature card carries more than one certificate: the Spanish DNIe
// and most Italian cards hold one to authenticate and one to sign. Taking the
// first pair the driver returned, as the tool did before, signed with whichever
// the card happened to list first.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/entrypoint/cli"
	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// cardWithTwoCertificates puts an authentication and a signature certificate
// on one token, the way a national identity card carries them.
func cardWithTwoCertificates(t *testing.T, firstUsage, secondUsage string) (softHSM, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	token := startSoftHSM(t)
	token.keyPair(t, "01", "authentication")
	token.keyPair(t, "02", "signature")

	first := issueCertificateWithUsage(t, token, "01", firstUsage)
	if first == nil {
		t.Skip("openssl is not available to issue a certificate")
	}
	importCertificate(t, token, "01", "authentication", first)
	second := issueCertificateWithUsage(t, token, "02", secondUsage)
	importCertificate(t, token, "02", "signature", second)

	return token, parsePEMCertificate(t, first), parsePEMCertificate(t, second)
}

func parsePEMCertificate(t *testing.T, content []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("the issued certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	return certificate
}

func loadFromCard(t *testing.T, module, label, pin string, choice domain.CertificateChoice) (infrastructure.KeyPair, error) {
	t.Helper()

	signer, err := domain.NewSigner(domain.NameFromCertificate, domain.FromToken,
		domain.WithToken(module, label, pin), domain.WithCertificateChoice(choice))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	pair, err := infrastructure.LoadKeyPair(signer)
	if err == nil {
		// The session ends at once, as it ends after a signature: one card
		// session exists at a time, and the certificate stays readable.
		_ = pair.Close()
	}
	return pair, err
}

// TestTheSignatureCertificateOfACardSigns: without a name, the certificate that
// declares non-repudiation signs, never the authentication one.
func TestTheSignatureCertificateOfACardSigns(t *testing.T) {
	token, authentication, signature := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	pair, err := loadFromCard(t, token.module, token.label, token.pin, domain.ChooseCertificateBy(""))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !pair.Certificate.Equal(signature) {
		t.Errorf("signed with serial %s, want the signature certificate %s (authentication is %s)",
			pair.Certificate.SerialNumber.Text(16), signature.SerialNumber.Text(16),
			authentication.SerialNumber.Text(16))
	}
	if pair.Name != "Token Test Signer" {
		t.Errorf("the signer name must be the holder, got %q", pair.Name)
	}
}

// TestACardCertificateIsChosenBySerial: the person can still pick the other
// one, by the serial the listing prints.
func TestACardCertificateIsChosenBySerial(t *testing.T) {
	token, authentication, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	pair, err := loadFromCard(t, token.module, token.label, token.pin,
		domain.ChooseCertificateBy(authentication.SerialNumber.Text(16)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !pair.Certificate.Equal(authentication) {
		t.Errorf("signed with serial %s, want %s", pair.Certificate.SerialNumber.Text(16),
			authentication.SerialNumber.Text(16))
	}
}

// TestTheCardIsFoundByItsCertificate: naming the certificate is enough; the
// reader that holds it is found without a token label.
func TestTheCardIsFoundByItsCertificate(t *testing.T) {
	token, authentication, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	pair, err := loadFromCard(t, token.module, "", token.pin,
		domain.ChooseCertificateBy(domain.Fingerprint(authentication)[:16]))
	if err != nil {
		t.Fatalf("load without a label: %v", err)
	}
	if !pair.Certificate.Equal(authentication) {
		t.Errorf("signed with serial %s, want %s", pair.Certificate.SerialNumber.Text(16),
			authentication.SerialNumber.Text(16))
	}
}

// TestTwoSigningCertificatesAreNotGuessed: when both can sign, the error lists
// them with what names each one.
func TestTwoSigningCertificatesAreNotGuessed(t *testing.T) {
	token, first, second := cardWithTwoCertificates(t, "nonRepudiation", "nonRepudiation")

	_, err := loadFromCard(t, token.module, token.label, token.pin, domain.ChooseCertificateBy(""))
	if !errors.Is(err, domain.ErrSeveralCertificates) {
		t.Fatalf("two signing certificates must not be guessed, got %v", err)
	}
	for _, certificate := range []*x509.Certificate{first, second} {
		if !strings.Contains(err.Error(), certificate.SerialNumber.Text(16)) {
			t.Errorf("the error must list serial %s: %v", certificate.SerialNumber.Text(16), err)
		}
		if !strings.Contains(err.Error(), domain.Fingerprint(certificate)) {
			t.Errorf("the error must list the fingerprint of %s", certificate.SerialNumber.Text(16))
		}
	}
}

// TestAnAbsentCertificateIsNotReplaced: a serial that is not on the card fails;
// signing with another certificate would be signing in someone else's name.
func TestAnAbsentCertificateIsNotReplaced(t *testing.T) {
	token, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	_, err := loadFromCard(t, token.module, token.label, token.pin, domain.ChooseCertificateBy("fffffffffff1"))
	if !errors.Is(err, domain.ErrNoCertificateMatches) {
		t.Fatalf("an absent certificate must be refused, got %v", err)
	}

	_, err = loadFromCard(t, token.module, "", token.pin, domain.ChooseCertificateBy("fffffffffff1"))
	if !errors.Is(err, domain.ErrNoCertificateMatches) {
		t.Fatalf("an absent certificate must be refused in every reader, got %v", err)
	}
}

// TestSeveralCardsAreNotGuessed: with two cards in the readers and neither
// named, the tool asks instead of picking one.
func TestSeveralCardsAreNotGuessed(t *testing.T) {
	first, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")
	cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	_, err := loadFromCard(t, first.module, "", first.pin, domain.ChooseCertificateBy(""))
	if err == nil || !strings.Contains(err.Error(), "several cards") {
		t.Fatalf("two cards must not be guessed, got %v", err)
	}
}

// TestTheListingShowsWhichCertificateSigns: the choice is visible before
// anything is signed.
func TestTheListingShowsWhichCertificateSigns(t *testing.T) {
	token, _, signature := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	slots, err := infrastructure.TokenInspector{Module: token.module}.Inspect()
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	for _, slot := range slots {
		if slot.TokenLabel != token.label {
			continue
		}
		if len(slot.Certificates) != 2 {
			t.Fatalf("the card holds two certificates, listed %d", len(slot.Certificates))
		}
		for _, certificate := range slot.Certificates {
			wanted := certificate.Serial == signature.SerialNumber.Text(16)
			if certificate.SignsByDefault != wanted {
				t.Errorf("certificate %s: signs by default %t, want %t",
					certificate.Serial, certificate.SignsByDefault, wanted)
			}
			if len(certificate.Fingerprint) != 64 {
				t.Errorf("certificate %s: fingerprint %q", certificate.Serial, certificate.Fingerprint)
			}
		}
		return
	}
	t.Fatalf("token %q not listed", token.label)
}

// TestTheCommandLineSignsWithTheNamedCertificate is the whole path: the CLI
// with --certificate and no --token, checked by OpenSSL, which reports the
// certificate that actually signed.
func TestTheCommandLineSignsWithTheNamedCertificate(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not available")
	}
	token, authentication, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")

	directory := t.TempDir()
	document := filepath.Join(directory, "lettera.txt")
	if err := os.WriteFile(document, []byte("Firmato con il certificato scelto\n"), 0o600); err != nil {
		t.Fatalf("write document: %v", err)
	}
	t.Setenv("TREBARUNA_PIN", token.pin)

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"sign", document, "--format", "cades", "--module", token.module,
		"--certificate", authentication.SerialNumber.Text(16)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("sign exited %d: %s", code, stderr.String())
	}

	signerPath := filepath.Join(directory, "signer.pem")
	verify := exec.Command(openssl, "cms", "-verify", "-noverify", "-inform", "DER",
		"-in", document+".p7m", "-signer", signerPath, "-out", os.DevNull)
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("openssl cms -verify: %v\n%s", err, output)
	}
	if signed := parsePEMCertificate(t, readFileOrFail(t, signerPath)); !signed.Equal(authentication) {
		t.Errorf("OpenSSL reports serial %s as the signer, want %s",
			signed.SerialNumber.Text(16), authentication.SerialNumber.Text(16))
	}
}

// TestACardInsertedAfterASignatureIsSeen guards the session release: a process
// that keeps running after a signature, like the local API, must see a card
// inserted afterwards. Before the sessions were closed, the driver stayed
// initialised and kept answering with the readers of the first signature.
func TestACardInsertedAfterASignatureIsSeen(t *testing.T) {
	first, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")
	sign := func(token softHSM) error {
		signer, err := domain.NewSigner(domain.NameFromCertificate, domain.FromToken,
			domain.WithToken(token.module, token.label, token.pin))
		if err != nil {
			return err
		}
		_, err = infrastructure.NewCadesSigner(nil).SignCades(context.Background(), application.CadesRequest{
			Content: []byte("documento\n"), Signer: signer, Level: domain.BES,
		})
		return err
	}
	if err := sign(first); err != nil {
		t.Fatalf("first signature: %v", err)
	}

	later, _, _ := cardWithTwoCertificates(t, "digitalSignature", "nonRepudiation")
	if err := sign(later); err != nil {
		t.Fatalf("a card inserted after the first signature was not seen: %v", err)
	}
}
