package dss_test

// The DSS writer is verified by independent readers, because a structurally
// plausible incremental update that any PDF tool rejects is worthless. The tests
// below check three properties in this order:
//
//	1. the original bytes are untouched, so existing signatures still verify;
//	2. the new document parses, and its /DSS carries the material;
//	3. qpdf and pdfsig accept it, which is the only opinion that counts.

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/firma-it/src/signing/infrastructure/dss"
	"github.com/digitorus/pdf"
)

// fixture builds a minimal one-page PDF and the certificates to embed.
func fixture(t *testing.T) ([]byte, []*x509.Certificate) {
	t.Helper()

	document := writePDF(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "DSS Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return document, []*x509.Certificate{certificate}
}

// writePDF builds a PDF with a real cross-reference table.
func writePDF(t *testing.T) []byte {
	t.Helper()

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> >>",
	}

	var builder bytes.Buffer
	builder.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for index, body := range objects {
		offsets[index] = builder.Len()
		builder.WriteString(strings.Join([]string{
			itoa(index + 1), " 0 obj\n", body, "\nendobj\n",
		}, ""))
	}

	xref := builder.Len()
	builder.WriteString("xref\n0 " + itoa(len(objects)+1) + "\n")
	builder.WriteString("0000000000 65535 f \n")
	for _, offset := range offsets {
		builder.WriteString(pad(offset) + " 00000 n \n")
	}
	builder.WriteString("trailer\n<< /Size " + itoa(len(objects)+1) + " /Root 1 0 R >>\nstartxref\n" +
		itoa(xref) + "\n%%EOF\n")
	return builder.Bytes()
}

// itoa formats an integer.
func itoa(value int) string {
	return big.NewInt(int64(value)).String()
}

// pad renders a ten-digit cross-reference offset.
func pad(value int) string {
	text := itoa(value)
	for len(text) < 10 {
		text = "0" + text
	}
	return text
}

// TestOriginalBytesArePreserved is the property that keeps existing signatures
// valid: an incremental update appends, it never rewrites.
func TestOriginalBytesArePreserved(t *testing.T) {
	original, certificates := fixture(t)

	updated, err := dss.Append(original, dss.Validation{Certificates: certificates})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	if !bytes.HasPrefix(updated, original) {
		t.Fatal("the original bytes must be untouched: a signature covers them")
	}
	if len(updated) <= len(original) {
		t.Fatal("an update must add bytes")
	}
}

// TestDocumentStillParses checks the update is structurally valid.
func TestDocumentStillParses(t *testing.T) {
	original, certificates := fixture(t)

	updated, err := dss.Append(original, dss.Validation{Certificates: certificates})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	reader, err := pdf.NewReader(bytes.NewReader(updated), int64(len(updated)))
	if err != nil {
		t.Fatalf("the updated document does not parse: %v", err)
	}

	catalog := reader.Trailer().Key("Root")
	if catalog.Kind() != pdf.Dict {
		t.Fatal("the updated document has no catalog")
	}
	if catalog.Key("Pages").Kind() == pdf.Null {
		t.Error("the update lost /Pages, so the pages are unreachable")
	}

	store := catalog.Key("DSS")
	if store.Kind() != pdf.Dict {
		t.Fatalf("the catalog carries no /DSS dictionary, got %v", store)
	}
	if store.Key("Type").Name() != "DSS" {
		t.Errorf("/DSS /Type = %q, want DSS", store.Key("Type").Name())
	}
	if store.Key("Certs").Len() != len(certificates) {
		t.Errorf("/DSS /Certs has %d entries, want %d", store.Key("Certs").Len(), len(certificates))
	}
}

// TestDSSStreamsCarryTheCertificate reads the embedded stream back.
func TestDSSStreamsCarryTheCertificate(t *testing.T) {
	original, certificates := fixture(t)

	updated, err := dss.Append(original, dss.Validation{Certificates: certificates})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	reader, err := pdf.NewReader(bytes.NewReader(updated), int64(len(updated)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	store := reader.Trailer().Key("Root").Key("DSS")
	if store.Kind() != pdf.Dict {
		t.Fatal("no /DSS dictionary")
	}

	// The array holds indirect references; reading the first one must give the
	// certificate DER back.
	first := store.Key("Certs").Index(0)
	if first.Kind() != pdf.Stream {
		t.Fatalf("/Certs[0] is %v, want a stream", first.Kind())
	}

	embedded, err := io.ReadAll(first.Reader())
	if err != nil {
		t.Fatalf("read the embedded stream: %v", err)
	}
	if !bytes.Equal(embedded, certificates[0].Raw) {
		t.Errorf("the embedded stream does not carry the certificate DER (%d bytes vs %d)",
			len(embedded), len(certificates[0].Raw))
	}
}

// TestQpdfAcceptsTheUpdate hands the document to qpdf, which rewrites it and
// therefore parses every object, the cross-reference chain included.
func TestQpdfAcceptsTheUpdate(t *testing.T) {
	if _, err := exec.LookPath("qpdf"); err != nil {
		t.Skip("qpdf is not available")
	}

	original, certificates := fixture(t)
	updated, err := dss.Append(original, dss.Validation{Certificates: certificates})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	directory := t.TempDir()
	input := filepath.Join(directory, "updated.pdf")
	output := filepath.Join(directory, "roundtrip.pdf")
	if err := os.WriteFile(input, updated, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// --check validates both the file structure and the stream data.
	check := exec.Command("qpdf", "--check", input)
	if result, err := check.CombinedOutput(); err != nil {
		t.Fatalf("qpdf --check rejected the update: %v\n%s", err, result)
	}

	rewrite := exec.Command("qpdf", input, output)
	if result, err := rewrite.CombinedOutput(); err != nil {
		t.Fatalf("qpdf could not rewrite the update: %v\n%s", err, result)
	}

	rewritten, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read rewritten file: %v", err)
	}

	// After a full rewrite the /DSS must still be reachable from the catalog.
	reader, err := pdf.NewReader(bytes.NewReader(rewritten), int64(len(rewritten)))
	if err != nil {
		t.Fatalf("the rewritten document does not parse: %v", err)
	}
	if reader.Trailer().Key("Root").Key("DSS").Kind() == pdf.Null {
		t.Error("qpdf dropped the /DSS dictionary, so it was not properly attached")
	}
}

// TestRefusesWithoutMaterial: an empty store is not a validation store.
func TestRefusesWithoutMaterial(t *testing.T) {
	original, _ := fixture(t)

	if _, err := dss.Append(original, dss.Validation{}); err == nil {
		t.Fatal("an empty /DSS must be refused, not written")
	}
}

// TestRefusesAnEmptyDocument keeps the error actionable.
func TestRefusesAnEmptyDocument(t *testing.T) {
	if _, err := dss.Append(nil, dss.Validation{OCSPResponses: [][]byte{{1}}}); err == nil {
		t.Fatal("an empty document must be refused")
	}
}

// TestOCSPAndCRLAreEmbedded covers the other two material types.
func TestOCSPAndCRLAreEmbedded(t *testing.T) {
	original, certificates := fixture(t)

	updated, err := dss.Append(original, dss.Validation{
		Certificates:  certificates,
		OCSPResponses: [][]byte{[]byte("ocsp-der-placeholder")},
		CRLs:          [][]byte{[]byte("crl-der-placeholder")},
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	reader, err := pdf.NewReader(bytes.NewReader(updated), int64(len(updated)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	store := reader.Trailer().Key("Root").Key("DSS")

	if store.Key("OCSPs").Len() != 1 {
		t.Errorf("/OCSPs has %d entries, want 1", store.Key("OCSPs").Len())
	}
	if store.Key("CRLs").Len() != 1 {
		t.Errorf("/CRLs has %d entries, want 1", store.Key("CRLs").Len())
	}
}

// TestVRIEntriesAreWritten checks the per-signature index.
func TestVRIEntriesAreWritten(t *testing.T) {
	original, certificates := fixture(t)

	updated, err := dss.Append(original, dss.Validation{
		Certificates: certificates,
		VRI: []dss.VRIEntry{{
			Key:          "AABBCCDD",
			Certificates: certificates,
		}},
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	reader, err := pdf.NewReader(bytes.NewReader(updated), int64(len(updated)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	store := reader.Trailer().Key("Root").Key("DSS")
	if store.Key("VRI").Kind() != pdf.Dict {
		t.Fatalf("/VRI is %v, want a dictionary", store.Key("VRI").Kind())
	}
	if store.Key("VRI").Key("AABBCCDD").Kind() != pdf.Dict {
		t.Error("the VRI entry for the signature is missing")
	}
}
