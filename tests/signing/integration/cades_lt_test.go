package integration_test

// CAdES-LT and CAdES-LTA, verified with OpenSSL rather than by inspecting our own
// output: the attributes have standard OIDs, and a wrong one produces a container
// that parses while meaning something else. That happened — revocationValues was
// written with the certificateValues OID — and only an independent parser showed it.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/anvius/trebaruna/src/signing/application"
	signingdomain "codeberg.org/anvius/trebaruna/src/signing/domain"
	"codeberg.org/anvius/trebaruna/src/signing/infrastructure"
)

// cadesFixture returns a document and a signer whose certificate publishes an OCSP
// responder, which LT requires.
func cadesFixture(t *testing.T) ([]byte, signingdomain.Signer) {
	t.Helper()
	return ltaFixture(t)
}

// TestCadesLtNeedsARevocationSource: LT is an opt-in network operation.
func TestCadesLtNeedsARevocationSource(t *testing.T) {
	content, signer := cadesFixture(t)

	_, err := infrastructure.NewCadesSigner(newLocalTSA(t)).SignCades(context.Background(),
		application.CadesRequest{
			Content:      content,
			Signer:       signer,
			Level:        signingdomain.LT,
			TimestampURL: "http://tsa.example.invalid",
		})
	if err == nil {
		t.Fatal("CAdES-LT without --online-revocation must be refused")
	}
	if !strings.Contains(err.Error(), "--online-revocation") {
		t.Errorf("the error must name the flag that fixes it, got: %v", err)
	}
}

// TestCadesLtCarriesRevocationValues checks the attribute OpenSSL calls
// id-smime-aa-ets-revocationValues, which is the one and only correct name.
func TestCadesLtCarriesRevocationValues(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}

	content, signer := cadesFixture(t)
	tsa := newLocalTSA(t)

	signed, err := infrastructure.NewCadesSigner(tsa).SignCades(context.Background(),
		application.CadesRequest{
			Content:         content,
			Signer:          signer,
			Level:           signingdomain.LT,
			TimestampURL:    "http://tsa.example.invalid",
			EmbedRevocation: true,
		})
	if err != nil {
		t.Fatalf("sign CAdES-LT: %v", err)
	}

	path := filepath.Join(t.TempDir(), "lt.p7m")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	output := runAsn1Parse(t, path)
	if !strings.Contains(output, "revocationValues") {
		t.Errorf("the container carries no revocationValues attribute:\n%s", output)
	}
	// The neighbouring OID means "certificateValues"; carrying OCSP responses
	// under that name is worse than failing, because it looks correct.
	if strings.Contains(output, "certValues") {
		t.Error("the container mislabels its revocation material as certValues")
	}
}

// TestCadesLtStillVerifiesWithOpenSSL: adding unsigned attributes must not touch
// the signature they sit beside.
func TestCadesLtStillVerifiesWithOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}

	content, signer := cadesFixture(t)
	tsa := newLocalTSA(t)

	signed, err := infrastructure.NewCadesSigner(tsa).SignCades(context.Background(),
		application.CadesRequest{
			Content:         content,
			Signer:          signer,
			Level:           signingdomain.LT,
			TimestampURL:    "http://tsa.example.invalid",
			EmbedRevocation: true,
		})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	directory := t.TempDir()
	container := filepath.Join(directory, "lt.p7m")
	if err := os.WriteFile(container, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The fixture's CA issues the signing certificate, so it is the anchor.
	keyPair, err := infrastructure.LoadKeyPair(signer)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	anchor := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(anchor, pemEncodeCertificate(keyPair.Chain[0]), 0o644); err != nil {
		t.Fatalf("write anchor: %v", err)
	}

	command := exec.Command("openssl", "cms", "-verify", "-inform", "DER",
		"-in", container, "-CAfile", anchor, "-purpose", "any", "-cades", "-out", os.DevNull)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("the CAdES-LT container does not verify: %v\n%s", err, output)
	}
}

// TestCadesLtaAddsTheArchiveTimeStamp: LTA is LT plus a token over everything.
func TestCadesLtaAddsTheArchiveTimeStamp(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}

	content, signer := cadesFixture(t)
	tsa := newLocalTSA(t)

	lt, err := infrastructure.NewCadesSigner(tsa).SignCades(context.Background(),
		application.CadesRequest{
			Content: content, Signer: signer, Level: signingdomain.LT,
			TimestampURL: "http://tsa.example.invalid", EmbedRevocation: true,
		})
	if err != nil {
		t.Fatalf("sign LT: %v", err)
	}

	lta, err := infrastructure.NewCadesSigner(tsa).SignCades(context.Background(),
		application.CadesRequest{
			Content: content, Signer: signer, Level: signingdomain.LTA,
			TimestampURL: "http://tsa.example.invalid", EmbedRevocation: true,
		})
	if err != nil {
		t.Fatalf("sign LTA: %v", err)
	}

	if len(lta) <= len(lt) {
		t.Fatalf("LTA (%d bytes) is not larger than LT (%d bytes): no archive timestamp was added",
			len(lta), len(lt))
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "lta.p7m")
	if err := os.WriteFile(path, lta, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	output := runAsn1Parse(t, path)
	if !strings.Contains(output, "archiveTimestamp") {
		t.Errorf("the container carries no archive timestamp:\n%s", output)
	}

	// The archive timestamp must come after the revocation material: it covers it.
	revocationAt := strings.Index(output, "revocationValues")
	archiveAt := strings.Index(output, "archiveTimestamp")
	if revocationAt < 0 || archiveAt < revocationAt {
		t.Error("the archive timestamp must be written after the revocation material it covers")
	}
}

// TestCadesBesAndTAreUnchanged guards the boundary: neither carries revocation.
func TestCadesBesAndTAreUnchanged(t *testing.T) {
	content, signer := cadesFixture(t)

	for _, level := range []signingdomain.Level{signingdomain.BES, signingdomain.T} {
		signed, err := infrastructure.NewCadesSigner(newLocalTSA(t)).SignCades(context.Background(),
			application.CadesRequest{
				Content: content, Signer: signer, Level: level,
				TimestampURL: "http://tsa.example.invalid",
			})
		if err != nil {
			t.Fatalf("%s: %v", level, err)
		}
		if bytes.Contains(signed, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x24}) {
			t.Errorf("%s carries a revocationValues attribute it should not have", level)
		}
	}
}

// runAsn1Parse dumps a DER file through OpenSSL's parser.
func runAsn1Parse(t *testing.T, path string) string {
	t.Helper()

	command := exec.Command("openssl", "asn1parse", "-inform", "DER", "-in", path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse: %v\n%s", err, output)
	}
	return string(output)
}
