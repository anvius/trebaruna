package integration_test

// End-to-end proof that a timestamp authority is authenticated, not merely
// present. The token is produced the way a TSA produces one: a TSTInfo signed as
// CMS with the id-ct-TSTInfo content type, wrapped in a TimeStampResp.
//
// Before this, the verifier could only say "the imprint is bound". It now says
// whether the authority that sealed it is a qualified service of an
// authenticated list.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	trustdomain "codeberg.org/simplicer/trebaruna/src/trust/domain"
	verificationapp "codeberg.org/simplicer/trebaruna/src/verification/application"
	verification "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// oidTSTInfo is the content type a timestamp token declares.
var oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

// timestampUnit is a TSA: a CA and the end-entity certificate that seals.
type timestampUnit struct {
	ca       *x509.Certificate
	signer   *x509.Certificate
	signerID crypto.Signer
}

// newTimestampUnit builds a CA and a timestamp certificate carrying the
// id-kp-timeStamping purpose, which ETSI EN 319 412-4 requires.
func newTimestampUnit(t *testing.T, withTimeStamping bool) timestampUnit {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(500),
		Subject:               pkix.Name{CommonName: "Example Qualified TSA CA", Organization: []string{"Example TSP"}},
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
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(501),
		Subject:      pkix.Name{CommonName: "Example Qualified TSA 1", Organization: []string{"Example TSP"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if withTimeStamping {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create TSA certificate: %v", err)
	}
	signer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse TSA certificate: %v", err)
	}

	return timestampUnit{ca: ca, signer: signer, signerID: key}
}

// tstInfo is the ASN.1 the token carries.
type tstInfo struct {
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
}

// seal builds a TimeStampResp over an imprint, as a TSA would.
func (u timestampUnit) seal(t *testing.T, imprint []byte, at time.Time) []byte {
	t.Helper()

	info := tstInfo{
		Version:      1,
		Policy:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
		SerialNumber: big.NewInt(7),
		GenTime:      at.UTC(),
	}
	info.MessageImprint.HashAlgorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	info.MessageImprint.HashedMessage = imprint

	encoded, err := asn1.Marshal(info)
	if err != nil {
		t.Fatalf("marshal TSTInfo: %v", err)
	}

	signature, err := cms.Sign(cms.Request{
		Content:         encoded,
		Certificate:     u.signer,
		Chain:           []*x509.Certificate{u.ca},
		Signer:          u.signerID,
		EmbeddedContent: true,
		ContentType:     oidTSTInfo,
	})
	if err != nil {
		t.Fatalf("sign TSTInfo: %v", err)
	}

	// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, token ContentInfo }
	status := []byte{0x30, 0x03, 0x02, 0x01, 0x00} // SEQUENCE { INTEGER 0 }
	body := append(append([]byte{}, status...), signature.DER...)

	return derEnvelope(body)
}

// derEnvelope wraps elements in a DER SEQUENCE.
func derEnvelope(body []byte) []byte {
	out := []byte{0x30}
	length := len(body)
	switch {
	case length < 0x80:
		out = append(out, byte(length))
	case length < 0x100:
		out = append(out, 0x81, byte(length))
	default:
		out = append(out, 0x82, byte(length>>8), byte(length))
	}
	return append(out, body...)
}

// TestTimestampAuthorityIsAccredited is the end-to-end guard.
func TestTimestampAuthorityIsAccredited(t *testing.T) {
	unit := newTimestampUnit(t, true)
	directory := t.TempDir()

	// A CAdES container whose signature value the token will seal.
	content := []byte("Contenuto firmato\n")
	signed, err := cms.Sign(cms.Request{
		Content:         content,
		Certificate:     unit.signer,
		Chain:           []*x509.Certificate{unit.ca},
		Signer:          unit.signerID,
		EmbeddedContent: true,
	})
	if err != nil {
		t.Fatalf("sign content: %v", err)
	}

	// The TSA seals the digest of the signature value, which is the binding rule.
	imprint := sha256.Sum256(signed.SignatureValue)
	tokenAt := time.Now().Truncate(time.Second)
	response := unit.seal(t, imprint[:], tokenAt)

	container, err := signed.WithTimestamp(response)
	if err != nil {
		t.Fatalf("attach timestamp: %v", err)
	}

	path := filepath.Join(directory, "sealed.p7m")
	if err := os.WriteFile(path, container, 0o644); err != nil {
		t.Fatalf("write container: %v", err)
	}

	list := trustdomain.TrustList{
		Territory:     "IT",
		Authenticated: true,
		Services: []trustdomain.TrustService{{
			ProviderName: "Example TSP",
			ServiceName:  "Example Qualified TSA",
			ServiceType:  "TSA/QTST",
			Status:       trustdomain.StatusGranted,
			StatusSince:  time.Now().Add(-24 * time.Hour),
			Qualified:    true,
			// The list publishes the authority's CA.
			Certificates: []*x509.Certificate{unit.ca},
		}},
	}

	useCase := verificationapp.NewVerifyDocument(
		nil, verificationinfra.NewCadesVerifier(),
		staticTrust{list: list}, fixedClock{moment: time.Now()},
	)

	report, err := useCase.Execute(verificationapp.Request{Path: path, Format: "cades"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(report.Signers) != 1 {
		t.Fatalf("signers = %d, want 1", len(report.Signers))
	}

	got := report.Signers[0]
	if !got.Timestamped {
		t.Fatal("the container carries a token, so the report must say so")
	}
	evidence := got.TimestampEvidence
	if !evidence.Bound {
		t.Error("the imprint matches the signature, so the token is bound")
	}
	if !evidence.CertificateCanTimestamp {
		t.Error("the TSA certificate carries id-kp-timeStamping")
	}
	if !evidence.ServiceListed {
		t.Errorf("the list publishes the issuing CA; unmatched: %+v", evidence)
	}
	if !evidence.Accredited {
		t.Errorf("the authority is qualified and granted, so it must be accredited")
	}
	if !hasFindingCode(got.Findings, "timestamp.accredited") {
		t.Error("an accredited token must carry its finding")
	}
	if hasFindingCode(got.Findings, "timestamp.untrusted_authority") {
		t.Error("an accredited token must not be reported as untrusted")
	}
}

// TestTimestampAuthorityWithoutTheListStaysUnproven: the same token, no list.
func TestTimestampAuthorityWithoutTheListStaysUnproven(t *testing.T) {
	unit := newTimestampUnit(t, true)
	directory := t.TempDir()

	signed, err := cms.Sign(cms.Request{
		Content:         []byte("Contenuto\n"),
		Certificate:     unit.signer,
		Chain:           []*x509.Certificate{unit.ca},
		Signer:          unit.signerID,
		EmbeddedContent: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	imprint := sha256.Sum256(signed.SignatureValue)
	container, err := signed.WithTimestamp(unit.seal(t, imprint[:], time.Now().Truncate(time.Second)))
	if err != nil {
		t.Fatalf("attach timestamp: %v", err)
	}

	path := filepath.Join(directory, "sealed.p7m")
	if err := os.WriteFile(path, container, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	useCase := verificationapp.NewVerifyDocument(
		nil, verificationinfra.NewCadesVerifier(),
		staticTrust{}, fixedClock{moment: time.Now()},
	)

	report, err := useCase.Execute(verificationapp.Request{Path: path, Format: "cades"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	got := report.Signers[0]
	if got.TimestampEvidence.Accredited {
		t.Error("without an authenticated list the authority cannot be accredited")
	}
	if !hasFindingCode(got.Findings, "timestamp.untrusted_authority") {
		t.Error("the report must say the authority is unproven")
	}
}

// TestTimestampWithoutTimeStampingUsageIsNotAccredited: the list matches, but
// the certificate is not a timestamp certificate.
func TestTimestampWithoutTimeStampingUsageIsNotAccredited(t *testing.T) {
	unit := newTimestampUnit(t, false)
	directory := t.TempDir()

	signed, err := cms.Sign(cms.Request{
		Content:         []byte("Contenuto\n"),
		Certificate:     unit.signer,
		Chain:           []*x509.Certificate{unit.ca},
		Signer:          unit.signerID,
		EmbeddedContent: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	imprint := sha256.Sum256(signed.SignatureValue)
	container, err := signed.WithTimestamp(unit.seal(t, imprint[:], time.Now().Truncate(time.Second)))
	if err != nil {
		t.Fatalf("attach timestamp: %v", err)
	}

	path := filepath.Join(directory, "sealed.p7m")
	if err := os.WriteFile(path, container, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	list := trustdomain.TrustList{
		Territory:     "IT",
		Authenticated: true,
		Services: []trustdomain.TrustService{{
			ProviderName: "Example TSP",
			ServiceType:  "TSA/QTST",
			Status:       trustdomain.StatusGranted,
			Qualified:    true,
			Certificates: []*x509.Certificate{unit.ca},
		}},
	}

	useCase := verificationapp.NewVerifyDocument(
		nil, verificationinfra.NewCadesVerifier(),
		staticTrust{list: list}, fixedClock{moment: time.Now()},
	)

	report, err := useCase.Execute(verificationapp.Request{Path: path, Format: "cades"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	got := report.Signers[0]
	if got.TimestampEvidence.Accredited {
		t.Error("a certificate without id-kp-timeStamping must not be accredited")
	}
	if !hasFindingCode(got.Findings, "timestamp.not_timestamping_certificate") {
		t.Error("the missing key usage must be reported")
	}
}

// TestTimestampBeforeTheGrantIsNotAccredited: the authority was approved after
// the seal was made, so it cannot have issued it.
func TestTimestampBeforeTheGrantIsNotAccredited(t *testing.T) {
	unit := newTimestampUnit(t, true)
	directory := t.TempDir()

	signed, err := cms.Sign(cms.Request{
		Content:         []byte("Contenuto\n"),
		Certificate:     unit.signer,
		Chain:           []*x509.Certificate{unit.ca},
		Signer:          unit.signerID,
		EmbeddedContent: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sealedAt := time.Now().Truncate(time.Second)
	imprint := sha256.Sum256(signed.SignatureValue)
	container, err := signed.WithTimestamp(unit.seal(t, imprint[:], sealedAt))
	if err != nil {
		t.Fatalf("attach timestamp: %v", err)
	}

	path := filepath.Join(directory, "sealed.p7m")
	if err := os.WriteFile(path, container, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	list := trustdomain.TrustList{
		Territory:     "IT",
		Authenticated: true,
		Services: []trustdomain.TrustService{{
			ProviderName: "Example TSP",
			ServiceType:  "TSA/QTST",
			Status:       trustdomain.StatusGranted,
			// Granted a month after the token was issued.
			StatusSince:  sealedAt.Add(30 * 24 * time.Hour),
			Qualified:    true,
			Certificates: []*x509.Certificate{unit.ca},
		}},
	}

	useCase := verificationapp.NewVerifyDocument(
		nil, verificationinfra.NewCadesVerifier(),
		staticTrust{list: list}, fixedClock{moment: time.Now()},
	)

	report, err := useCase.Execute(verificationapp.Request{Path: path, Format: "cades"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if report.Signers[0].TimestampEvidence.Accredited {
		t.Error("a token issued before the grant cannot be accredited")
	}
}

// TestTimestampListPublishingTheEndEntityMatches: several states publish the
// time-stamping unit's own certificate instead of its CA (measured: LT 15 of 15
// services, NL 9 of 9, PL 17 of 19). A verifier that only compares issuers would
// declare every one of those authorities unproven.
func TestTimestampListPublishingTheEndEntityMatches(t *testing.T) {
	unit := newTimestampUnit(t, true)
	directory := t.TempDir()

	signed, err := cms.Sign(cms.Request{
		Content:         []byte("Contenuto\n"),
		Certificate:     unit.signer,
		Chain:           []*x509.Certificate{unit.ca},
		Signer:          unit.signerID,
		EmbeddedContent: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	imprint := sha256.Sum256(signed.SignatureValue)
	container, err := signed.WithTimestamp(unit.seal(t, imprint[:], time.Now().Truncate(time.Second)))
	if err != nil {
		t.Fatalf("attach timestamp: %v", err)
	}

	path := filepath.Join(directory, "sealed.p7m")
	if err := os.WriteFile(path, container, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	list := trustdomain.TrustList{
		Territory:     "LT",
		Authenticated: true,
		Services: []trustdomain.TrustService{{
			ProviderName: "Example TSP",
			ServiceType:  "TSA/QTST",
			Status:       trustdomain.StatusGranted,
			Qualified:    true,
			// The list publishes the unit itself, not its issuer.
			Certificates: []*x509.Certificate{unit.signer},
		}},
	}

	useCase := verificationapp.NewVerifyDocument(
		nil, verificationinfra.NewCadesVerifier(),
		staticTrust{list: list}, fixedClock{moment: time.Now()},
	)

	report, err := useCase.Execute(verificationapp.Request{Path: path, Format: "cades"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	evidence := report.Signers[0].TimestampEvidence
	if !evidence.ServiceListed {
		t.Errorf("the list publishes this exact certificate, so it must match: %+v", evidence)
	}
	if !evidence.Accredited {
		t.Error("a granted TSA/QTST publishing this certificate accredits the token")
	}
}

// hasFindingCode reports whether a code appears in the findings.
func hasFindingCode(findings []verification.Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

// TestCadesChainUsesTheTimestampMoment is the CAdES counterpart of the PDF fix:
// a certificate that was valid when the sealed signature was made, but has
// expired since, must not read as an untrusted issuer.
func TestCadesChainUsesTheTimestampMoment(t *testing.T) {
	unit := newTimestampUnit(t, true)
	directory := t.TempDir()

	signed, err := cms.Sign(cms.Request{
		Content:         []byte("Contenuto\n"),
		Certificate:     unit.signer,
		Chain:           []*x509.Certificate{unit.ca},
		Signer:          unit.signerID,
		EmbeddedContent: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The token is issued now, which is inside the TSA certificate's window.
	imprint := sha256.Sum256(signed.SignatureValue)
	container, err := signed.WithTimestamp(unit.seal(t, imprint[:], time.Now().Truncate(time.Second)))
	if err != nil {
		t.Fatalf("attach timestamp: %v", err)
	}

	path := filepath.Join(directory, "sealed.p7m")
	if err := os.WriteFile(path, container, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	list := trustdomain.TrustList{
		Territory:     "IT",
		Authenticated: true,
		Services: []trustdomain.TrustService{{
			ProviderName: "Example TSP",
			ServiceType:  "CA/QC",
			Status:       trustdomain.StatusGranted,
			Qualified:    true,
			Certificates: []*x509.Certificate{unit.ca},
		}},
	}

	// Verify as if ten years had passed: every certificate here has expired by
	// then, but the token proves the signature was made before that.
	future := time.Now().AddDate(10, 0, 0)
	useCase := verificationapp.NewVerifyDocument(
		nil, verificationinfra.NewCadesVerifier(),
		staticTrust{list: list}, fixedClock{moment: future},
	)

	report, err := useCase.Execute(verificationapp.Request{Path: path, Format: "cades"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	got := report.Signers[0]
	if got.CertificateStatus == verification.StatusUnknown {
		t.Errorf("the chain must be judged at the timestamp, not at %s; findings: %+v",
			future.Format("2006-01-02"), got.Findings)
	}
}
