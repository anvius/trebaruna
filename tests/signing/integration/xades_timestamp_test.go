package integration_test

// XAdES-T is the level that adds proof of when the signature existed. ETSI
// EN 319 132-1 requires the token to seal the canonical form of ds:SignatureValue
// and to live inside xades:UnsignedProperties, which is the only place it can go:
// it did not exist when the signature was computed.
//
// The tests below produce a real token from a local TSA and check both halves:
// the token verifies with OpenSSL, and its imprint matches the SignatureValue
// element the signed file actually carries. Getting the first without the second
// is the classic mistake, and it produces a token that proves nothing.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"golang.org/x/crypto/ocsp"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// oidTSTInfoXades is the content type a timestamp token declares.
var oidTSTInfoXades = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

// xadesTestSigner builds the fixture signer used across the XAdES tests.
func xadesTestSigner(t *testing.T) domain.Signer {
	t.Helper()

	fixture := newFixture(t)
	return buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
}

// localTSA is a timestamper that signs tokens in process, so the test needs no
// network and the token is still a real RFC 3161 structure.
type localTSA struct {
	certificate *x509.Certificate
	ca          *x509.Certificate
	// decoys are certificates the token carries before the authority's
	// issuer: one may bear its name with another key.
	decoys   []*x509.Certificate
	key      *rsa.PrivateKey
	requests int
	imprint  []byte
	// nonce is echoed when set, which the PDF signer requires.
	nonce []byte
}

// Token builds a TimeStampResp over the digest it is given.
//
// The imprint is exactly the bytes received: a TSA that appends or truncates
// here produces a token that parses and proves nothing, which is what the
// OpenSSL test exists to catch.
func (t *localTSA) Token(_ context.Context, digest []byte, _, _, _ string) ([]byte, error) {
	t.requests++
	t.imprint = append([]byte{}, digest...)

	info := struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint struct {
			HashAlgorithm struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			HashedMessage []byte
		}
		SerialNumber *big.Int
		GenTime      time.Time `asn1:"generalized"`
		Nonce        *big.Int  `asn1:"optional"`
	}{
		Version:      1,
		Policy:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
		SerialNumber: big.NewInt(1),
		GenTime:      time.Now().UTC(),
	}
	if len(t.nonce) > 0 {
		info.Nonce = new(big.Int).SetBytes(t.nonce)
	}
	info.MessageImprint.HashAlgorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	info.MessageImprint.HashedMessage = append([]byte{}, digest[:len(digest)]...)

	encoded, err := asn1.Marshal(info)
	if err != nil {
		return nil, err
	}

	signature, err := cms.Sign(cms.Request{
		Content:         encoded,
		Certificate:     t.certificate,
		Chain:           append(append([]*x509.Certificate{}, t.decoys...), t.ca),
		Signer:          t.key,
		EmbeddedContent: true,
		ContentType:     oidTSTInfoXades,
	})
	if err != nil {
		return nil, err
	}

	status := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	return derSequence(append(status, signature.DER...)), nil
}

// derSequence wraps bytes in a DER SEQUENCE.
func derSequence(body []byte) []byte {
	out := []byte{0x30}
	switch n := len(body); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, body...)
}

// newLocalTSA builds the CA and the timestamp certificate.
func newLocalTSA(t *testing.T) *localTSA {
	t.Helper()
	return newTimestampAuthority(t, false, false)
}

// newLocalTSAWithStatus is newLocalTSA whose certificate names an OCSP
// responder, local, that answers for it with the CA's key, as a qualified
// authority's certificate does.
func newLocalTSAWithStatus(t *testing.T) *localTSA {
	t.Helper()
	return newTimestampAuthority(t, true, false)
}

// newRevokedLocalTSA is newLocalTSAWithStatus whose responder says its
// certificate is revoked.
func newRevokedLocalTSA(t *testing.T) *localTSA {
	t.Helper()
	return newTimestampAuthority(t, true, true)
}

func newTimestampAuthority(t *testing.T, withStatus, revoked bool) *localTSA {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(700),
		Subject:               pkix.Name{CommonName: "XAdES Test TSA CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	// ETSI EN 319 412-4 requires the timeStamping purpose to be critical.
	// OpenSSL's "unsuitable certificate purpose" is exactly the complaint when it
	// is not, and a real TSA always marks it.
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		t.Fatalf("marshal extended key usage: %v", err)
	}
	var responder []string
	if withStatus {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			body, _ := io.ReadAll(request.Body)
			parsed, err := ocsp.ParseRequest(body)
			if err != nil {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			state := ocsp.Response{Status: ocsp.Good, SerialNumber: parsed.SerialNumber,
				ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}
			if revoked {
				state.Status, state.RevokedAt, state.RevocationReason = ocsp.Revoked, time.Now().Add(-time.Hour), ocsp.KeyCompromise
			}
			answer, err := ocsp.CreateResponse(ca, ca, state, caKey)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			writer.Header().Set("Content-Type", "application/ocsp-response")
			writer.Write(answer)
		}))
		t.Cleanup(server.Close)
		responder = []string{server.URL}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(701),
		OCSPServer:   responder,
		Subject:      pkix.Name{CommonName: "XAdES Test TSA"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
			Critical: true,
			Value:    eku,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create TSA certificate: %v", err)
	}
	certificate, _ := x509.ParseCertificate(der)

	return &localTSA{certificate: certificate, ca: ca, key: key}
}

// TestXadesTimestampNeedsAnAuthority: refusing with a reason beats emitting a
// signature that claims a level it does not have.
func TestXadesTimestampNeedsAnAuthority(t *testing.T) {
	signer := xadesTestSigner(t)
	request := buildXadesRequest(signer, []byte(`<a>1</a>`), false)
	request.Level = domain.T

	_, err := infrastructure.NewXadesSigner(nil).SignXades(context.Background(), request)
	if err == nil {
		t.Fatal("XAdES-T without a TSA must be refused")
	}
	if !strings.Contains(err.Error(), "--tsa") {
		t.Errorf("the error must say how to fix it, got: %v", err)
	}
}

// TestXadesTimestampIsEmitted: the token must appear in the right place.
func TestXadesTimestampIsEmitted(t *testing.T) {
	tsa := newLocalTSA(t)
	signer := xadesTestSigner(t)

	request := buildXadesRequest(signer, []byte(`<fattura><numero>7</numero></fattura>`), false)
	request.Level = domain.T
	request.TimestampURL = "http://tsa.example.invalid"

	output, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed := string(output)

	if tsa.requests != 1 {
		t.Errorf("the TSA was called %d times, want 1", tsa.requests)
	}
	if !strings.Contains(signed, "UnsignedProperties") {
		t.Fatal("XAdES-T must carry xades:UnsignedProperties")
	}
	if !strings.Contains(signed, "SignatureTimeStamp") {
		t.Fatal("XAdES-T must carry xades:SignatureTimeStamp")
	}
	if !strings.Contains(signed, "EncapsulatedTimeStamp") {
		t.Fatal("the token must be an xades:EncapsulatedTimeStamp")
	}

	// The token must be inside the unsigned properties, not floating in the doc.
	unsignedStart := strings.Index(signed, "<xades:UnsignedProperties")
	tokenIndex := strings.Index(signed, "<xades:EncapsulatedTimeStamp>")
	if unsignedStart < 0 || tokenIndex < unsignedStart {
		t.Error("the token must live inside xades:UnsignedProperties")
	}
}

// TestXadesTimestampImprintCoversSignatureValue is the test that separates a real
// XAdES-T from one that merely contains a token: the imprint must be the digest
// of the SignatureValue element as it appears in the file.
func TestXadesTimestampImprintCoversSignatureValue(t *testing.T) {
	tsa := newLocalTSA(t)
	signer := xadesTestSigner(t)

	request := buildXadesRequest(signer, []byte(`<atto><id>1</id></atto>`), false)
	request.Level = domain.T
	request.TimestampURL = "http://tsa.example.invalid"

	output, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// EN 319 132-1, 5.4.1.3: the token covers ds:SignatureValue canonicalised
	// where it stands, its inherited namespaces included; read back from the
	// produced bytes, as a verifier would.
	element := canonicalSignatureValueOf(t, output)
	if !bytes.Contains(element, []byte(`<ds:SignatureValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`)) {
		t.Fatalf("the canonical form declares its namespaces: %.120s", element)
	}
	digest := sha256.Sum256(element)
	if !bytes.Equal(digest[:], tsa.imprint) {
		t.Errorf("the token imprint does not cover the canonical ds:SignatureValue\n  file: %x\n  token: %x",
			digest, tsa.imprint)
	}
	raw := sha256.Sum256(regexp.MustCompile(`(?s)<ds:SignatureValue[^>]*>.*?</ds:SignatureValue>`).Find(output))
	if bytes.Equal(raw[:], tsa.imprint) {
		t.Error("the token must not cover the element as written (trebaruna before 0.55.2)")
	}
}

// canonicalSignatureValueOf canonicalises ds:SignatureValue in a signed file.
func canonicalSignatureValueOf(t *testing.T, signed []byte) []byte {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	value := document.FindElement("//SignatureValue")
	if value == nil {
		t.Fatal("the signed file carries no ds:SignatureValue")
	}
	canonical, err := xmldsig.Canonicalize(value, xmldsig.C14N10, "")
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

// TestXadesTimestampTokenVerifiesWithOpenSSL hands the token to an independent
// implementation, which is the only way to know it is a real token.
func TestXadesTimestampTokenVerifiesWithOpenSSL(t *testing.T) {
	tsa := newLocalTSA(t)
	signer := xadesTestSigner(t)

	request := buildXadesRequest(signer, []byte(`<atto><id>2</id></atto>`), false)
	request.Level = domain.T
	request.TimestampURL = "http://tsa.example.invalid"

	output, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Extract the base64 token and decode it.
	match := regexp.MustCompile(`<xades:EncapsulatedTimeStamp>([^<]+)</xades:EncapsulatedTimeStamp>`).FindSubmatch(output)
	if match == nil {
		t.Fatal("no encapsulated token found")
	}
	tokenDER, err := base64.StdEncoding.DecodeString(string(match[1]))
	if err != nil {
		t.Fatalf("the token is not valid base64: %v", err)
	}

	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token.tsr")
	// -token_in wants the bare PKCS#7 ContentInfo, not the TimeStampResp that
	// wraps it: the status is transport, the token is the evidence.
	if err := os.WriteFile(tokenPath, tokenDER, 0o644); err != nil {
		t.Fatalf("write token: %v", err)
	}

	// The token's own signature is checked by openssl ts, with the TSA as anchor.
	caPath := filepath.Join(directory, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tsa.ca.Raw})
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	if !hasOpenSSL(t) {
		t.Skip("openssl is not available")
	}

	// -data is the *content* the imprint covers, not the imprint itself: OpenSSL
	// hashes it and compares. The content here is ds:SignatureValue in its
	// canonical form, which is what the token must seal.
	element := canonicalSignatureValueOf(t, output)
	coveredPath := filepath.Join(directory, "covered.bin")
	if err := os.WriteFile(coveredPath, element, 0o644); err != nil {
		t.Fatalf("write the covered content: %v", err)
	}

	// The token uses SHA-256, so OpenSSL must be told which digest to use.
	runOpenSSL(t, "ts", "-verify", "-token_in", "-in", tokenPath,
		"-data", coveredPath, "-CAfile", caPath, "-untrusted", caPath)
}

// hasOpenSSL reports whether the openssl tool is present.
func hasOpenSSL(t *testing.T) bool {
	t.Helper()
	_, err := exec.LookPath("openssl")
	return err == nil
}

// runOpenSSL runs openssl and fails the test when it does not succeed.
func runOpenSSL(t *testing.T, arguments ...string) {
	t.Helper()

	command := exec.Command("openssl", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s failed: %v\n%s", strings.Join(arguments, " "), err, output)
	}
}

// TestXadesBesIsUnchanged guards the level boundary: BES must not carry a token.
func TestXadesBesIsUnchanged(t *testing.T) {
	tsa := newLocalTSA(t)
	signer := xadesTestSigner(t)

	request := buildXadesRequest(signer, []byte(`<a>1</a>`), false)
	request.Level = domain.BES

	output, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Contains(string(output), "UnsignedProperties") {
		t.Error("BES must not carry the timestamp extension")
	}
	if tsa.requests != 0 {
		t.Error("BES must not contact a timestamp authority")
	}
}

// TestVerifierReadsXadesTimestamp is the round trip: what the signer emits, the
// verifier must read back as a bound token from a real authority.
func TestVerifierReadsXadesTimestamp(t *testing.T) {
	tsa := newLocalTSA(t)
	signer := xadesTestSigner(t)

	request := buildXadesRequest(signer, []byte(`<fattura><n>9</n></fattura>`), false)
	request.Level = domain.T
	request.TimestampURL = "http://tsa.example.invalid"

	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	path := filepath.Join(t.TempDir(), "signed.xml")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	got := reports[0]
	if !got.Timestamped {
		t.Fatalf("the file carries a signature timestamp, so the report must say so; findings: %+v", got.Findings)
	}
	if !got.TimestampEvidence.Bound {
		t.Error("the token covers this SignatureValue")
	}
	if !got.TimestampEvidence.CertificateCanTimestamp {
		t.Error("the TSA certificate carries id-kp-timeStamping")
	}
	if got.TimestampAuthority == "" {
		t.Error("the authority must be named")
	}
	if got.SignedAt.IsZero() {
		t.Error("the token supplies the signing time")
	}
}

// TestVerifierRejectsATokenFromAnotherSignature is the security property: a
// valid token that covers different bytes must not be accepted.
func TestVerifierRejectsATokenFromAnotherSignature(t *testing.T) {
	tsa := newLocalTSA(t)
	signer := xadesTestSigner(t)

	build := func(document string) []byte {
		request := buildXadesRequest(signer, []byte(document), false)
		request.Level = domain.T
		request.TimestampURL = "http://tsa.example.invalid"
		signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}

	first := build(`<a><n>1</n></a>`)
	second := build(`<a><n>2</n></a>`)

	// Take the token from the first and paste it into the second.
	tokenPattern := regexp.MustCompile(`<xades:EncapsulatedTimeStamp>([^<]+)</xades:EncapsulatedTimeStamp>`)
	firstToken := tokenPattern.FindSubmatch(first)
	if firstToken == nil {
		t.Fatal("the first document carries no token")
	}
	tampered := tokenPattern.ReplaceAll(second, []byte(
		"<xades:EncapsulatedTimeStamp>"+string(firstToken[1])+"</xades:EncapsulatedTimeStamp>"))

	path := filepath.Join(t.TempDir(), "tampered.xml")
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	got := reports[0]
	for _, finding := range got.Findings {
		if finding.Code == "timestamp.invalid" && finding.Status == "bad" {
			return
		}
	}
	t.Errorf("a token lifted from another signature must be rejected; findings: %+v", got.Findings)
}

// TestXadesLtaReplacesTheRefusal keeps the regression visible: LTA used to be
// accepted and produced a B-T file while the CLI printed "level lta". The level
// must now be the one the file actually carries, and it must need a TSA.
func TestXadesLtaReplacesTheRefusal(t *testing.T) {
	signer := xadesTestSigner(t)

	// Without an authority there is no archive timestamp to add.
	request := buildXadesRequest(signer, []byte(`<a>1</a>`), false)
	request.Level = domain.LTA

	_, err := infrastructure.NewXadesSigner(nil).SignXades(context.Background(), request)
	if err == nil {
		t.Fatal("XAdES-A without a timestamp authority must be refused")
	}
	if !strings.Contains(err.Error(), "--tsa") {
		t.Errorf("the error must name --tsa, got: %v", err)
	}

	// LTA also needs revocation material, which is a separate, opt-in step.
	request.TimestampURL = "http://tsa.example.invalid"
	request.EmbedRevocation = true
	if _, err := infrastructure.NewXadesSigner(nil).SignXades(context.Background(), request); err == nil {
		t.Fatal("XAdES-LTA without a revocation source must be refused")
	}

	// With one, the file must really carry the archive property.
	tsa := newLocalTSA(t)
	_, revocationSigner := ltaFixture(t)
	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err == nil {
		t.Fatal("a signer without an OCSP responder cannot satisfy LTA")
	}

	request.Signer = revocationSigner
	signed, err = infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.Contains(string(signed), "ArchiveTimeStamp") {
		t.Error("the produced file must carry the archive timestamp, not merely claim the level")
	}
}

// TestXadesLtaEmitsArchiveTimeStamp pins the structure XAdES-A requires.
//
// The archive timestamp covers the signed document and every object the
// signature already has (xades_archive_test.go rebuilds its input), which is
// why it must be the outermost layer; it lives in the 1.4.1 namespace rather
// than the 1.3.2 one.
func TestXadesLtaEmitsArchiveTimeStamp(t *testing.T) {
	tsa := newLocalTSA(t)
	signer := xadesTestSigner(t)

	_, signer = ltaFixture(t)
	request := buildXadesRequest(signer, []byte(`<fattura><n>3</n></fattura>`), false)
	request.Level = domain.LTA
	request.TimestampURL = "http://tsa.example.invalid"
	request.EmbedRevocation = true

	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	document := string(signed)

	if !strings.Contains(document, "ArchiveTimeStamp") {
		t.Fatal("XAdES-A must carry xades141:ArchiveTimeStamp")
	}
	if !strings.Contains(document, "http://uri.etsi.org/01903/v1.4.1#") {
		t.Error("the archive property belongs to the 1.4.1 namespace")
	}
	if tsa.requests != 2 {
		t.Errorf("the TSA was called %d times, want 2 (signature and archive timestamps)", tsa.requests)
	}

	// The archive timestamp must come after the signature timestamp, because it
	// covers it: writing it first would leave the signature timestamp unsealed.
	signatureIndex := strings.Index(document, "SignatureTimeStamp")
	archiveIndex := strings.Index(document, "ArchiveTimeStamp")
	if signatureIndex < 0 || archiveIndex < signatureIndex {
		t.Error("the archive timestamp must be written after the signature timestamp it covers")
	}
}

// TestVerifierReadsArchiveTimeStamp is the round trip for the archival level.
func TestVerifierReadsArchiveTimeStamp(t *testing.T) {
	tsa := newLocalTSA(t)
	signer := xadesTestSigner(t)

	_, signer = ltaFixture(t)
	request := buildXadesRequest(signer, []byte(`<atto><n>4</n></atto>`), false)
	request.Level = domain.LTA
	request.TimestampURL = "http://tsa.example.invalid"
	request.EmbedRevocation = true

	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	path := filepath.Join(t.TempDir(), "lta.xml")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	got := reports[0]
	if got.Integrity != "good" {
		t.Errorf("integrity = %s, the signature must still verify with the archive layer present", got.Integrity)
	}

	found := false
	for _, finding := range got.Findings {
		if finding.Code == "timestamp.archival" && finding.Status == "good" {
			found = true
		}
	}
	if !found {
		t.Errorf("the archive timestamp must be reported; findings: %+v", got.Findings)
	}
	if !got.Timestamped {
		t.Error("XAdES-A implies XAdES-T, so the signature timestamp must be present too")
	}
}

// TestATimestampOverTheOldFormIsAcceptedAndTold: files trebaruna wrote
// before 0.55.2 sealed ds:SignatureValue as written. They still read as
// timestamped, with a warning that other validators will refuse them; a
// new file carries no such warning.
func TestATimestampOverTheOldFormIsAcceptedAndTold(t *testing.T) {
	tsa := newLocalTSA(t)
	signer := xadesTestSigner(t)
	request := buildXadesRequest(signer, []byte(`<fattura><n>10</n></fattura>`), false)
	request.Level = domain.T
	request.TimestampURL = "http://tsa.example.invalid"
	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	raw := sha256.Sum256(regexp.MustCompile(`(?s)<ds:SignatureValue[^>]*>.*?</ds:SignatureValue>`).Find(signed))
	response, err := tsa.Token(context.Background(), raw[:], "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := cms.ExtractToken(response)
	if err != nil {
		t.Fatal(err)
	}
	old := regexp.MustCompile(`<xades:EncapsulatedTimeStamp>[^<]+</xades:EncapsulatedTimeStamp>`).ReplaceAll(signed,
		[]byte("<xades:EncapsulatedTimeStamp>"+base64.StdEncoding.EncodeToString(oldToken)+"</xades:EncapsulatedTimeStamp>"))

	for name, content := range map[string][]byte{"new": signed, "old": old} {
		path := filepath.Join(t.TempDir(), name+".xml")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		reports, err := verificationinfra.NewXadesVerifier().Extract(path)
		if err != nil {
			t.Fatal(err)
		}
		legacy := false
		for _, finding := range reports[0].Findings {
			legacy = legacy || finding.Code == "timestamp.legacy_form"
		}
		if !reports[0].TimestampEvidence.Bound || legacy != (name == "old") {
			t.Errorf("%s: bound %v, legacy warning %v", name, reports[0].TimestampEvidence.Bound, legacy)
		}
	}
}

// TestAnArchiveTimestampOverAnotherSignatureIsTold: KeyInfo is outside the
// signature value but inside what the archive timestamp seals, so a change
// there after archiving leaves the signature valid and the archive
// timestamp proving nothing.
func TestAnArchiveTimestampOverAnotherSignatureIsTold(t *testing.T) {
	tsa := newLocalTSA(t)
	_, signer := ltaFixture(t)
	request := buildXadesRequest(signer, []byte(`<atto><n>5</n></atto>`), false)
	request.Level, request.TimestampURL, request.EmbedRevocation = domain.LTA, "http://tsa.example.invalid", true
	signed, err := infrastructure.NewXadesSigner(tsa).SignXades(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	changed := bytes.Replace(signed, []byte("<ds:KeyInfo>"), []byte(`<ds:KeyInfo Id="added-later">`), 1)
	if bytes.Equal(changed, signed) {
		t.Fatal("no KeyInfo to change")
	}
	path := filepath.Join(t.TempDir(), "changed.xml")
	if err := os.WriteFile(path, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewXadesVerifier().Extract(path)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	for _, finding := range reports[0].Findings {
		codes[finding.Code] = string(finding.Status)
	}
	if reports[0].Integrity != "good" || codes["timestamp.archive_unbound"] == "" || codes["timestamp.archival"] != "" {
		t.Errorf("integrity %s, findings %v", reports[0].Integrity, codes)
	}
}
