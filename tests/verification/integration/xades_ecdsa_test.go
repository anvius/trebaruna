package integration_test

// XML-DSig writes an ECDSA signature as r||s (RFC 6931 §2.3.6). Up to 0.6.3 the
// signer wrote the ASN.1 SEQUENCE instead and the verifier, built on goxmldsig,
// read only that SEQUENCE: each agreed with the other and disagreed with every
// other implementation. A correct ECDSA XAdES from another producer was
// reported as tampered. These tests pin both directions and the old files.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"
	signinginfra "codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

func signECDSAXades(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "MARIO ROSSI"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	signer, err := signingdomain.NewSigner(signingdomain.NameFromCertificate, signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signinginfra.NewXadesSigner(nil).SignXades(t.Context(), application.XadesRequest{
		Content: []byte(`<fattura><numero>1</numero></fattura>`), Signer: signer, Level: signingdomain.BES,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

func integrityOf(t *testing.T, document string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signed.xml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return string(extractOne(t, verificationinfra.NewXadesVerifier(), path).Integrity)
}

// signatureValue returns the decoded value and a function that replaces it.
func signatureValue(t *testing.T, document string) ([]byte, func([]byte) string) {
	t.Helper()
	opening := strings.Index(document, "<ds:SignatureValue")
	start := opening + strings.Index(document[opening:], ">") + 1
	end := strings.Index(document, "</ds:SignatureValue>")
	value, err := base64.StdEncoding.DecodeString(document[start:end])
	if err != nil {
		t.Fatal(err)
	}
	return value, func(replacement []byte) string {
		return document[:start] + base64.StdEncoding.EncodeToString(replacement) + document[end:]
	}
}

func TestAStandardECDSAXadesVerifies(t *testing.T) {
	document := signECDSAXades(t)
	if value, _ := signatureValue(t, document); len(value) != 64 {
		t.Fatalf("SignatureValue is %d bytes, want r||s", len(value))
	}
	if got := integrityOf(t, document); got != "good" {
		t.Errorf("integrity = %s: a correct r||s signature must verify", got)
	}
}

func TestAnECDSAXadesInTheOldASN1FormStillVerifies(t *testing.T) {
	document := signECDSAXades(t)
	value, replace := signatureValue(t, document)
	legacy, err := asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(value[:32]), new(big.Int).SetBytes(value[32:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := integrityOf(t, replace(legacy)); got != "good" {
		t.Errorf("integrity = %s: files written by 0.6.3 and earlier must keep verifying", got)
	}
}

func TestATamperedECDSAXadesIsStillBroken(t *testing.T) {
	document := strings.Replace(signECDSAXades(t), "<numero>1</numero>", "<numero>2</numero>", 1)
	if got := integrityOf(t, document); got != "bad" {
		t.Errorf("integrity = %s: changed content must not verify in either encoding", got)
	}
}
