package infrastructure_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// identity is a key in a .p12 and its certificate, as a person holds it.
func identity(t *testing.T, holder string, serial int64) (signing.Signer, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: holder},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	raw, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certificate, _ := x509.ParseCertificate(raw)
	bundle, err := pkcs12.Modern.Encode(key, certificate, nil, "x")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.NewSigner(signing.NameFromCertificate, signing.FromP12,
		signing.WithKeyMaterial(bundle), signing.WithPassphrase("x"))
	if err != nil {
		t.Fatal(err)
	}
	return signer, certificate
}

func onePagePDF() []byte {
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>"}
	var pdf strings.Builder
	pdf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for index, object := range objects {
		offsets[index] = pdf.Len()
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", index+1, object)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return []byte(pdf.String())
}

func format(t *testing.T, name string) domain.Format {
	t.Helper()
	parsed, err := domain.ParseFormat(name)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func write(t *testing.T, directory, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func opensslVerify(t *testing.T, arguments ...string) {
	t.Helper()
	if output, err := exec.Command("openssl", append([]string{"cms", "-verify", "-noverify", "-inform", "DER", "-out", os.DevNull}, arguments...)...).CombinedOutput(); err != nil {
		t.Fatalf("openssl cms -verify %v: %v\n%s", arguments, err, output)
	}
}

// TestCAdESForAPageVerifiesInOpenSSL: implicit by default, explicit with
// mode=explicit, and a co-signature over the first.
func TestCAdESForAPageVerifiesInOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	maria, mariaCertificate := identity(t, "MARIA GARCIA", 11)
	signer := infrastructure.NewNativePageSigner()
	data := []byte("solicitud de la sede\n")
	directory := t.TempDir()

	implicit, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Sign, Format: format(t, "CAdES"),
		Algorithm: "SHA256withECDSA", Properties: map[string]string{}, Data: data, Key: maria})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(implicit.Certificate, mariaCertificate.Raw) {
		t.Error("the answer must carry the signer's certificate")
	}
	opensslVerify(t, "-in", write(t, directory, "implicit.p7m", implicit.Signature))

	explicit, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Sign, Format: format(t, "CAdES"),
		Algorithm: "SHA256", Properties: map[string]string{"mode": "explicit"}, Data: data, Key: maria})
	if err != nil {
		t.Fatal(err)
	}
	opensslVerify(t, "-in", write(t, directory, "explicit.p7s", explicit.Signature), "-content", write(t, directory, "data", data), "-binary")

	luca, _ := identity(t, "LUCA BIANCHI", 12)
	cosigned, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Cosign, Format: format(t, "auto"),
		Algorithm: "SHA256", Properties: map[string]string{}, Data: implicit.Signature, Key: luca})
	if err != nil {
		t.Fatal(err)
	}
	signers := filepath.Join(directory, "signers.pem")
	opensslVerify(t, "-in", write(t, directory, "cosigned.p7m", cosigned.Signature), "-signer", signers)
	if count := bytes.Count(readFile(t, signers), []byte("BEGIN CERTIFICATE")); count != 2 {
		t.Errorf("the co-signed envelope has %d signers, want 2", count)
	}
}

// TestPAdESForAPageIsInvisibleUnlessPlaced, as AutoFirma's.
func TestPAdESForAPageIsInvisibleUnlessPlaced(t *testing.T) {
	if _, err := exec.LookPath("pdfsig"); err != nil {
		t.Skip("pdfsig is not available")
	}
	maria, _ := identity(t, "MARIA GARCIA", 13)
	signer := infrastructure.NewNativePageSigner()
	directory := t.TempDir()
	for name, properties := range map[string]map[string]string{
		"invisible": {},
		"placed": {"signaturePage": "1", "signaturePositionOnPageLowerLeftX": "60", "signaturePositionOnPageLowerLeftY": "60",
			"signaturePositionOnPageUpperRightX": "260", "signaturePositionOnPageUpperRightY": "140", "signReason": "Trámite"},
	} {
		signed, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Sign, Format: format(t, "PAdES"),
			Algorithm: "SHA256", Properties: properties, Data: onePagePDF(), Key: maria})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		path := write(t, directory, name+".pdf", signed.Signature)
		output, _ := exec.Command("pdfsig", path).CombinedOutput()
		if !strings.Contains(string(output), "Signature is Valid") {
			t.Errorf("%s: pdfsig says %s", name, output)
		}
		hasAppearance := bytes.Contains(signed.Signature, []byte("/AP"))
		if (name == "placed") != hasAppearance {
			t.Errorf("%s: appearance present %t", name, hasAppearance)
		}
	}
}

// TestWhatTrebarunaDoesNotDoYetIsRefusedByName: never a different signature
// than the one asked for.
func TestWhatTrebarunaDoesNotDoYetIsRefusedByName(t *testing.T) {
	maria, _ := identity(t, "MARIA GARCIA", 14)
	signer := infrastructure.NewNativePageSigner()
	cases := []struct {
		format     string
		properties map[string]string
		data       []byte
		want       domain.FailureCode
	}{
		{"CAdES", map[string]string{"precalculatedHashAlgorithm": "SHA-256"}, []byte("x"), domain.UnsupportedOperation},
		{"XAdES Detached", map[string]string{}, []byte("<a/>"), domain.UnsupportedFormat},
		{"XAdES", map[string]string{}, []byte("not xml"), domain.InvalidXML},
		{"PAdES", map[string]string{}, []byte("not a pdf"), domain.InvalidPDF},
		{"CAdES-ASiC-S", map[string]string{}, []byte("x"), domain.UnsupportedFormat},
	}
	for _, entry := range cases {
		_, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Sign, Format: format(t, entry.format),
			Algorithm: "SHA256", Properties: entry.properties, Data: entry.data, Key: maria})
		var failure domain.Failure
		if !errors.As(err, &failure) || failure.Code != entry.want {
			t.Errorf("%s %v: %v, want SAF_%02d", entry.format, entry.properties, err, entry.want)
		}
	}
	if _, err := signer.Sign(context.Background(), application.PageSignature{Crypto: domain.Cosign, Format: format(t, "CAdES"),
		Algorithm: "SHA256", Properties: map[string]string{}, Data: []byte("plain text"), Key: maria}); err == nil {
		t.Error("co-signing something that is not a signature must fail (SAF_31)")
	}
}

// TestSelectCertReturnsTheKeysCertificate.
func TestSelectCertReturnsTheKeysCertificate(t *testing.T) {
	maria, certificate := identity(t, "MARIA GARCIA", 15)
	raw, err := infrastructure.KeyCertificates{}.Certificate(maria)
	if err != nil || !bytes.Equal(raw, certificate.Raw) {
		t.Fatalf("got %v", err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
