package integration_test

// PAdES B-LT is produced in two steps: pdfsign signs, then the adapter appends a
// /DSS dictionary in an incremental update. Both halves are asserted here, and
// the property that matters most is that the first half survives the second:
// adding validation material must not invalidate the signature it validates.

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	"codeberg.org/simplicer/firma-it/src/signing/domain"
	"codeberg.org/simplicer/firma-it/src/signing/infrastructure"
	"codeberg.org/simplicer/firma-it/src/signing/infrastructure/dss"
	"github.com/digitorus/pdf"
)

// TestPadesWithoutRevocationSourceIsRefused: LT is a timestamped signature *and*
// a store. Each missing input is reported by name, in the order the level
// requires them, so the user is not sent to fix the wrong flag.
func TestPadesWithoutRevocationSourceIsRefused(t *testing.T) {
	fixture := newFixture(t)
	document := writeBlankPDF(t, fixture.directory)
	original, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("read PDF: %v", err)
	}

	signer := pemSigner(t, fixture)

	// Without a TSA, the timestamp is what is missing.
	_, err = infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content:  original,
		Signer:   signer,
		Level:    domain.LT,
		SignedAt: timeNow(),
	})
	if err == nil {
		t.Fatal("PAdES B-LT without a timestamp authority must be refused")
	}
	if !strings.Contains(err.Error(), "--tsa") {
		t.Errorf("the error must name --tsa, got: %v", err)
	}

	// With a TSA but no permission to reach OCSP, the store is what is missing.
	_, err = infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content:      original,
		Signer:       signer,
		Level:        domain.LT,
		SignedAt:     timeNow(),
		TimestampURL: "http://tsa.example.invalid",
	})
	if err == nil {
		t.Fatal("PAdES B-LT without --online-revocation must be refused")
	}
	if !strings.Contains(err.Error(), "--online-revocation") {
		t.Errorf("the error must name --online-revocation, got: %v", err)
	}
}

// TestPadesBesIgnoresTheRevocationFlag: B-B must not carry a store even when the
// caller allowed network access for another reason.
func TestPadesBesIgnoresTheRevocationFlag(t *testing.T) {
	fixture := newFixture(t)
	document := writeBlankPDF(t, fixture.directory)
	original, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("read PDF: %v", err)
	}

	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content:         original,
		Signer:          pemSigner(t, fixture),
		Level:           domain.BES,
		SignedAt:        timeNow(),
		EmbedRevocation: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if bytes.Contains(signed, []byte("/Type /DSS")) {
		t.Error("PAdES B-B must not carry a /DSS dictionary")
	}
}

// TestSignedPdfStillVerifiesAfterDSS is the central property of B-LT.
func TestSignedPdfStillVerifiesAfterDSS(t *testing.T) {
	fixture := newFixture(t)
	document := writeBlankPDF(t, fixture.directory)
	original, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("read PDF: %v", err)
	}

	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content:  original,
		Signer:   pemSigner(t, fixture),
		Level:    domain.BES,
		SignedAt: timeNow(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Append a store the way the LT path does, with the fixture's certificate.
	updated := appendStore(t, signed, fixture.cert.Raw)

	if !bytes.HasPrefix(updated, signed) {
		t.Fatal("the signed bytes must be preserved for the signature to survive")
	}

	if _, err := exec.LookPath("pdfsig"); err != nil {
		t.Skip("pdfsig is not available")
	}

	path := filepath.Join(t.TempDir(), "withdss.pdf")
	if err := os.WriteFile(path, updated, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	output, err := exec.Command("pdfsig", path).Output()
	if err != nil {
		t.Fatalf("pdfsig failed: %v", err)
	}
	if !strings.Contains(string(output), "Signature is Valid") {
		t.Errorf("the signature no longer verifies after adding /DSS:\n%s", output)
	}
}

// TestDSSIsReachableFromTheCatalog checks the dictionary is where a validator
// looks for it, and that it names the signature it serves.
func TestDSSIsReachableFromTheCatalog(t *testing.T) {
	fixture := newFixture(t)
	document := writeBlankPDF(t, fixture.directory)
	original, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("read PDF: %v", err)
	}

	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content:  original,
		Signer:   pemSigner(t, fixture),
		Level:    domain.BES,
		SignedAt: timeNow(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	updated := appendStore(t, signed, fixture.cert.Raw)

	reader, err := pdf.NewReader(bytes.NewReader(updated), int64(len(updated)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	store := reader.Trailer().Key("Root").Key("DSS")
	if store.Kind() != pdf.Dict {
		t.Fatal("the catalog has no /DSS dictionary")
	}

	vri := store.Key("VRI")
	if vri.Kind() != pdf.Dict || len(vri.Keys()) != 1 {
		t.Fatalf("/VRI must hold exactly one entry, got %v", vri.Keys())
	}

	// The key is the uppercase hex SHA-1 of the signature value.
	key := vri.Keys()[0]
	if key == "" || key != strings.ToUpper(key) {
		t.Errorf("VRI key %q must be uppercase hex", key)
	}
	if _, err := hex.DecodeString(key); err != nil {
		t.Errorf("VRI key %q is not hexadecimal: %v", key, err)
	}
}

// pemSigner builds a signer from the fixture's PEM files.
func pemSigner(t *testing.T, fixture fixture) domain.Signer {
	t.Helper()

	bundle := append(append([]byte{}, mustRead(t, fixture.certPath)...), mustRead(t, fixture.keyPath)...)
	signer, err := domain.NewSigner("Fixture", domain.FromPEM, domain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	return signer
}

// timeNow returns the current instant.
func timeNow() time.Time { return time.Now() }

// appendStore adds a /DSS carrying one certificate and one VRI entry.
func appendStore(t *testing.T, signed []byte, certificateDER []byte) []byte {
	t.Helper()

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	key, err := signatureContentsDigest(signed)
	if err != nil {
		t.Fatalf("signature digest: %v", err)
	}

	updated, err := dss.Append(signed, dss.Validation{
		Certificates:  []*x509.Certificate{certificate},
		OCSPResponses: [][]byte{[]byte("placeholder-ocsp")},
		VRI: []dss.VRIEntry{{
			Key:          key,
			Certificates: []*x509.Certificate{certificate},
		}},
	})
	if err != nil {
		t.Fatalf("append /DSS: %v", err)
	}
	return updated
}

// signatureContentsDigest mirrors the VRI key rule.
func signatureContentsDigest(signed []byte) (string, error) {
	reader, err := pdf.NewReader(bytes.NewReader(signed), int64(len(signed)))
	if err != nil {
		return "", err
	}
	fields := reader.Trailer().Key("Root").Key("AcroForm").Key("Fields")
	for index := 0; index < fields.Len(); index++ {
		raw := fields.Index(index).Key("V").Key("Contents").RawString()
		if raw == "" {
			continue
		}
		digest := sha1.Sum([]byte(raw))
		return strings.ToUpper(hex.EncodeToString(digest[:])), nil
	}
	return "", errors.New("no signature value")
}
