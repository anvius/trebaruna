package integration_test

// End-to-end QES detection: sign a real PDF with a certificate that carries the
// QcStatements a qualified CA emits, publish its issuer in a trust list, and
// check that the verifier reaches "qualified". Unit tests prove the decision
// logic; this proves the wiring, which is where the earlier gap lived: the
// anchors were correct and the verdict never left "advanced".

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/application"
	signingdomain "codeberg.org/simplicer/firma-it/src/signing/domain"
	"codeberg.org/simplicer/firma-it/src/signing/infrastructure"
	trustdomain "codeberg.org/simplicer/firma-it/src/trust/domain"
	verificationapp "codeberg.org/simplicer/firma-it/src/verification/application"
	verification "codeberg.org/simplicer/firma-it/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/firma-it/src/verification/infrastructure"
)

// qualifiedIssuer is a CA plus the leaf it issued, with the QC statements.
type qualifiedIssuer struct {
	ca      *x509.Certificate
	cert    *x509.Certificate
	certPEM []byte
	keyPEM  []byte
	key     *rsa.PrivateKey
}

// newQualifiedIssuer builds a CA and a signing certificate carrying QcCompliance
// and QcSSCD, the two statements a qualified signature certificate publishes.
func newQualifiedIssuer(t *testing.T) qualifiedIssuer {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Example Qualified CA G2", Organization: []string{"Example TSP"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	// qcStatements: QcCompliance + QcSSCD, encoded exactly as RFC 3739 defines.
	qcStatements, err := asn1.Marshal([]struct {
		ID asn1.ObjectIdentifier
	}{{asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}}, {asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}}})
	if err != nil {
		t.Fatalf("marshal qcStatements: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			CommonName:   "MARIA LOPEZ GARCIA",
			SerialNumber: "IDCES-00000000X",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3},
			Value: qcStatements,
		}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	return qualifiedIssuer{
		ca:      ca,
		cert:    leaf,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		key:     key,
	}
}

// TestSignedPdfReachesQualified is the end-to-end guard for QES detection.
func TestSignedPdfReachesQualified(t *testing.T) {
	issuer := newQualifiedIssuer(t)
	directory := t.TempDir()

	keyMaterial := append(append([]byte{}, issuer.certPEM...), issuer.keyPEM...)
	documentPath := writeBlankPDF(t, directory)
	original, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read blank pdf: %v", err)
	}

	signedAt := time.Now().Truncate(time.Second)
	signer, err := signingdomain.NewSigner("Example Signer", signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(keyMaterial))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content:  original,
		Signer:   signer,
		Level:    signingdomain.BES,
		SignedAt: signedAt,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	signedPath := filepath.Join(directory, "signed.pdf")
	if err := os.WriteFile(signedPath, signed, 0o644); err != nil {
		t.Fatalf("write signed pdf: %v", err)
	}

	// The trust list publishes the CA as a granted qualified service, which is
	// what an authenticated Italian-style list does.
	list := trustdomain.TrustList{
		Territory:     "IT",
		Authenticated: true,
		Services: []trustdomain.TrustService{{
			ProviderName: "Example TSP",
			ServiceName:  "Example Qualified CA G2",
			ServiceType:  "CA/QC",
			Status:       trustdomain.StatusGranted,
			StatusSince:  time.Now().Add(-24 * time.Hour),
			Qualified:    true,
			Certificates: []*x509.Certificate{issuer.ca},
		}},
	}

	verifier := verificationinfra.NewPDFVerifier()
	useCase := verificationapp.NewVerifyDocument(
		verifier, nil,
		staticTrust{list: list},
		fixedClock{moment: time.Now()},
	)

	report, err := useCase.Execute(verificationapp.Request{Path: signedPath, Territory: "IT"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(report.Signers) != 1 {
		t.Fatalf("signers = %d, want 1", len(report.Signers))
	}

	got := report.Signers[0]
	if got.Integrity != verification.StatusGood {
		t.Fatalf("integrity = %s, the signed PDF must verify", got.Integrity)
	}
	if !got.Claims.Compliant {
		t.Error("the verifier must read QcCompliance from the signed PDF's certificate")
	}
	if !got.Claims.DeviceQualified {
		t.Error("the verifier must read QcSSCD from the signed PDF's certificate")
	}
	if got.Trust != verification.TrustQualified {
		t.Errorf("trust = %s, want qualified; missing: %v", got.Trust, got.Qualification.Missing(got.SignedAt))
	}
}

// TestSignedPdfStaysAdvancedWithoutTheList: the same document, no trust list.
// The cryptography is intact but nobody vouches for the issuer.
func TestSignedPdfStaysAdvancedWithoutTheList(t *testing.T) {
	issuer := newQualifiedIssuer(t)
	directory := t.TempDir()

	keyMaterial := append(append([]byte{}, issuer.certPEM...), issuer.keyPEM...)
	signer, err := signingdomain.NewSigner("Example Signer", signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(keyMaterial))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	documentPath := writeBlankPDF(t, directory)
	original, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read blank pdf: %v", err)
	}

	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content:  original,
		Signer:   signer,
		Level:    signingdomain.BES,
		SignedAt: time.Now().Truncate(time.Second),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signedPath := filepath.Join(directory, "signed.pdf")
	if err := os.WriteFile(signedPath, signed, 0o644); err != nil {
		t.Fatalf("write signed pdf: %v", err)
	}

	useCase := verificationapp.NewVerifyDocument(
		verificationinfra.NewPDFVerifier(), nil,
		staticTrust{}, fixedClock{moment: time.Now()},
	)

	report, err := useCase.Execute(verificationapp.Request{Path: signedPath})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	got := report.Signers[0]
	if got.Trust == verification.TrustQualified {
		t.Error("without an authenticated list the signature cannot be qualified")
	}
	if got.Qualified {
		t.Error("the qualification flag must follow the evidence")
	}
}

// staticTrust serves one prepared list.
type staticTrust struct {
	list trustdomain.TrustList
}

// Load returns the prepared list.
func (s staticTrust) Load(string) (trustdomain.TrustList, error) { return s.list, nil }

// fixedClock freezes the evaluation moment.
type fixedClock struct{ moment time.Time }

// Now returns the frozen instant.
func (f fixedClock) Now() time.Time { return f.moment }

// writeBlankPDF writes a one-page PDF with a real cross-reference table.
//
// pdfsign parses the document before signing and refuses one whose startxref is
// missing, so a hand-written stub without the table cannot exercise the signing
// path at all.
func writeBlankPDF(t *testing.T, directory string) string {
	t.Helper()

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> >>",
	}

	var builder strings.Builder
	builder.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for index, body := range objects {
		offsets[index] = builder.Len()
		fmt.Fprintf(&builder, "%d 0 obj\n%s\nendobj\n", index+1, body)
	}

	xref := builder.Len()
	fmt.Fprintf(&builder, "xref\n0 %d\n", len(objects)+1)
	builder.WriteString("0000000000 65535 f \n")
	for _, offset := range offsets {
		fmt.Fprintf(&builder, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&builder, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, xref)

	path := filepath.Join(directory, "blank.pdf")
	if err := os.WriteFile(path, []byte(builder.String()), 0o644); err != nil {
		t.Fatalf("write PDF: %v", err)
	}
	return path
}
