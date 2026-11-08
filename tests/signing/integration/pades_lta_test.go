package integration_test

// PAdES B-LTA adds a document timestamp over everything written so far: the
// signature, the /DSS, and the whole file. ETSI EN 319 142-1 §6.4 requires it to
// cover the entire document, so anything appended afterwards breaks it.
//
// The verification here is deliberately done with OpenSSL rather than pdfsig:
// poppler reports "/SubFilter /ETSI.RFC3161" as "Signature Type: unknown" and
// refuses to verify it, which is a limitation of that tool, not of the artefact.
// OpenSSL checks the token against the exact bytes the ByteRange claims.

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	"codeberg.org/anvius/pignus/src/signing/application"
	"codeberg.org/anvius/pignus/src/signing/domain"
	"codeberg.org/anvius/pignus/src/signing/infrastructure"
	"golang.org/x/crypto/ocsp"
)

// TestPadesLtaNeedsATimestampAuthority: LTA is an archive *timestamp*, so
// without an authority there is nothing to add.
func TestPadesLtaNeedsATimestampAuthority(t *testing.T) {
	fixture := newFixture(t)
	original := readFile(t, writeBlankPDF(t, fixture.directory))

	_, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content:         original,
		Signer:          pemSigner(t, fixture),
		Level:           domain.LTA,
		SignedAt:        timeNow(),
		EmbedRevocation: true,
	})
	if err == nil {
		t.Fatal("LTA without a timestamp authority must be refused")
	}
	if !strings.Contains(err.Error(), "--tsa") {
		t.Errorf("the error must name the flag that fixes it, got: %v", err)
	}
}

// ltaFixture builds a document and a signer whose certificate publishes an OCSP
// responder, which B-LT requires: without an answer there is no /DSS to archive.
//
// The responder is local and signs real OCSP answers with the CA key, so the
// bytes that end up in /DSS are genuine.
func ltaFixture(t *testing.T) ([]byte, domain.Signer) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(800),
		Subject:               pkix.Name{CommonName: "LTA Test CA"},
		NotBefore:             timeNow().Add(-time.Hour),
		NotAfter:              timeNow().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
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

	// The responder must exist before the leaf is issued, because its URL goes
	// into the certificate.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		parsed, err := ocsp.ParseRequest(body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		answer, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: parsed.SerialNumber,
			ThisUpdate:   timeNow().Add(-time.Minute),
			NextUpdate:   timeNow().Add(time.Hour),
		}, caKey)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = writer.Write(answer)
	}))
	t.Cleanup(server.Close)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	usage, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 2}})
	if err != nil {
		t.Fatalf("marshal EKU: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(801),
		Subject:      pkix.Name{CommonName: "LTA Test Signer"},
		NotBefore:    timeNow().Add(-time.Hour),
		NotAfter:     timeNow().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		OCSPServer:   []string{server.URL},
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
			Critical: true,
			Value:    usage,
		}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	bundle := append(append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)

	signer, err := domain.NewSigner("LTA Fixture", domain.FromPEM, domain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	return blankPDFBytes(), signer
}

// blankPDFBytes returns a minimal one-page PDF with a valid xref table.
func blankPDFBytes() []byte {
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
	return builder.Bytes()
}

// tokenWithNonce builds a token that echoes the received nonce.
func (t *localTSA) tokenWithNonce(digest, nonce []byte) ([]byte, error) {
	previous := t.nonce
	t.nonce = nonce
	response, err := t.Token(context.Background(), digest, "", "", "")
	t.nonce = previous
	return response, err
}

// TestPadesLtaEmitsADocumentTimestamp checks the structure the level requires.
func TestPadesLtaEmitsADocumentTimestamp(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}

	tsa := newLocalTSA(t)
	original, signer := ltaFixture(t)

	signed, err := infrastructure.NewPadesSigner(tsa).SignPades(context.Background(), application.PadesRequest{
		Content:         original,
		Signer:          signer,
		Level:           domain.LTA,
		SignedAt:        timeNow(),
		TimestampURL:    tsa.url(t),
		EmbedRevocation: true,
	})
	if err != nil {
		t.Fatalf("sign LTA: %v", err)
	}

	if !bytes.Contains(signed, []byte("/DocTimeStamp")) {
		t.Fatal("B-LTA must carry a /DocTimeStamp signature")
	}
	if !bytes.Contains(signed, []byte("/SubFilter /ETSI.RFC3161")) {
		t.Fatal("the archive timestamp must declare /SubFilter /ETSI.RFC3161")
	}

	// The archive timestamp is the last revision: it covers the /DSS written
	// before it, which is the whole point of the level.
	dssIndex := bytes.Index(signed, []byte("/Type /DSS"))
	stampIndex := bytes.Index(signed, []byte("/DocTimeStamp"))
	if dssIndex < 0 {
		t.Fatal("B-LTA must embed the /DSS that B-LT provides")
	}
	if stampIndex < dssIndex {
		t.Error("the archive timestamp must come after the /DSS so that it covers it")
	}
}

// TestPadesLtaTimestampVerifiesWithOpenSSL is the independent check.
func TestPadesLtaTimestampVerifiesWithOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}

	tsa := newLocalTSA(t)
	original, signer := ltaFixture(t)

	signed, err := infrastructure.NewPadesSigner(tsa).SignPades(context.Background(), application.PadesRequest{
		Content:         original,
		Signer:          signer,
		Level:           domain.LTA,
		SignedAt:        timeNow(),
		TimestampURL:    tsa.url(t),
		EmbedRevocation: true,
	})
	if err != nil {
		t.Fatalf("sign LTA: %v", err)
	}

	directory := t.TempDir()
	documentPath := filepath.Join(directory, "lta.pdf")
	if err := os.WriteFile(documentPath, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	token, covered := extractArchiveTimestamp(t, signed)
	tokenPath := filepath.Join(directory, "archive.tsr")
	coveredPath := filepath.Join(directory, "covered.bin")
	caPath := filepath.Join(directory, "ca.pem")

	if err := os.WriteFile(tokenPath, token, 0o644); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if err := os.WriteFile(coveredPath, covered, 0o644); err != nil {
		t.Fatalf("write covered bytes: %v", err)
	}
	if err := os.WriteFile(caPath, pemEncodeCertificate(tsa.ca), 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	runOpenSSL(t, "ts", "-verify", "-token_in", "-in", tokenPath,
		"-data", coveredPath, "-CAfile", caPath, "-untrusted", caPath)
}

// extractArchiveTimestamp returns the token and the bytes its ByteRange covers.
func extractArchiveTimestamp(t *testing.T, document []byte) ([]byte, []byte) {
	t.Helper()

	start := bytes.Index(document, []byte("/DocTimeStamp"))
	if start < 0 {
		t.Fatal("no /DocTimeStamp found")
	}
	window := document[start:]

	// The ByteRange tells exactly which bytes the token seals.
	byteRange := regexp.MustCompile(`/ByteRange\s*\[([^\]]+)\]`).FindSubmatch(window)
	if byteRange == nil {
		t.Fatal("the archive timestamp has no /ByteRange")
	}
	fields := strings.Fields(string(byteRange[1]))
	if len(fields) != 4 {
		t.Fatalf("/ByteRange has %d fields, want 4", len(fields))
	}
	numbers := make([]int, 4)
	for index, field := range fields {
		value, err := strconv.Atoi(field)
		if err != nil {
			t.Fatalf("ByteRange field %q: %v", field, err)
		}
		numbers[index] = value
	}

	covered := append([]byte{}, document[numbers[0]:numbers[0]+numbers[1]]...)
	covered = append(covered, document[numbers[2]:numbers[2]+numbers[3]]...)

	// /Contents is a hex string padded to a fixed size; trim to its DER length.
	contentsStart := bytes.Index(window, []byte("/Contents<"))
	if contentsStart < 0 {
		t.Fatal("the archive timestamp has no /Contents")
	}
	hexStart := contentsStart + len("/Contents<")
	hexEnd := bytes.Index(window[hexStart:], []byte(">"))
	if hexEnd < 0 {
		t.Fatal("/Contents is not terminated")
	}

	encoded := string(window[hexStart : hexStart+hexEnd])
	if len(encoded)%2 != 0 {
		encoded = encoded[:len(encoded)-1]
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode /Contents: %v", err)
	}

	if len(raw) < 2 {
		t.Fatal("/Contents is too short to hold a token")
	}
	var total int
	if raw[1] < 0x80 {
		total = 2 + int(raw[1])
	} else {
		lengthBytes := int(raw[1] & 0x7f)
		if 2+lengthBytes > len(raw) {
			t.Fatal("/Contents declares a truncated length")
		}
		declared := 0
		for index := 0; index < lengthBytes; index++ {
			declared = declared<<8 | int(raw[2+index])
		}
		total = 2 + lengthBytes + declared
	}
	if total > len(raw) {
		t.Fatalf("/Contents declares %d bytes but holds %d", total, len(raw))
	}

	return raw[:total], covered
}

// url starts an HTTP endpoint that serves the in-process TSA over real HTTP.
//
// pdfsign calls the TSA itself, so the token must come back over the wire; the
// http.TestServer keeps the test offline while exercising that path.
func (t *localTSA) url(test *testing.T) string {
	test.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		// The request carries a MessageImprint; the digest is the last OCTET
		// STRING inside it, which is what the token must cover.
		digest := lastOctetString(body)
		if len(digest) != 32 {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		// Echo the nonce: pdfsign rejects a token whose nonce differs, and that
		// check is what stops a replayed response from another request.
		response, err := t.tokenWithNonce(digest, requestNonce(body))
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = writer.Write(response)
	}))
	test.Cleanup(server.Close)
	return server.URL
}

// lastOctetString returns the contents of the final OCTET STRING in a DER blob.
func lastOctetString(der []byte) []byte {
	position := 0
	for position < len(der) {
		if der[position] != 0x04 {
			position++
			continue
		}
		length, headerSize, ok := readDERLength(der, position+1)
		if !ok || position+1+headerSize+length > len(der) {
			return nil
		}
		value := der[position+1+headerSize : position+1+headerSize+length]
		if length >= 32 {
			return value
		}
		position++
	}
	return nil
}

// readDERLength decodes a DER length field.
func readDERLength(der []byte, offset int) (int, int, bool) {
	if offset >= len(der) {
		return 0, 0, false
	}
	first := der[offset]
	if first < 0x80 {
		return int(first), 1, true
	}
	count := int(first & 0x7f)
	if count == 0 || count > 4 || offset+1+count > len(der) {
		return 0, 0, false
	}
	length := 0
	for index := 0; index < count; index++ {
		length = length<<8 | int(der[offset+1+index])
	}
	return length, 1 + count, true
}

// requestNonce extracts the nonce from a TimeStampReq.
//
// The nonce is the last INTEGER in the structure, after the policy and before
// the optional extensions; scanning for the final 0x02 tag is enough for the
// requests this client emits.
func requestNonce(der []byte) []byte {
	var found []byte
	position := 0
	for position < len(der) {
		if der[position] != 0x02 {
			position++
			continue
		}
		length, headerSize, ok := readDERLength(der, position+1)
		if !ok || length == 0 || position+1+headerSize+length > len(der) {
			position++
			continue
		}
		value := der[position+1+headerSize : position+1+headerSize+length]
		// The version is a small integer; a nonce is long.
		if length > 4 {
			found = value
		}
		position++
	}
	return found
}

// pemEncodeCertificate renders a certificate as PEM.
func pemEncodeCertificate(certificate *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}
